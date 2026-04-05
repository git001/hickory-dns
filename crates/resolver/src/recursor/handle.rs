use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use async_recursion::async_recursion;
use futures_util::{StreamExt, stream};
use moka::sync::Cache as MokaCache;
use tracing::{debug, trace, warn};

use super::{
    DnssecPolicy, RecursorError, RecursorOptions, RootZoneDelegation, RootZoneDelegations,
    error::AuthorityData, is_subzone,
};
#[cfg(feature = "__tls")]
use crate::config::ConnectionConfig;
#[cfg(feature = "metrics")]
use crate::metrics::recursor::RecursorMetrics;
#[cfg(feature = "__dnssec")]
use crate::proto::dnssec::rdata::DNSSECRData;
use crate::{
    cache::{ResponseCache, TtlConfig},
    config::{NameServerConfig, OpportunisticEncryption, ResolverOpts},
    connection_provider::{ConnectionProvider, TlsConfig},
    name_server::NameServer,
    name_server_pool::{NameServerPool, NameServerTransportState, PoolContext},
    net::{DnsHandle, NetError},
    proto::{
        access_control::{AccessControlSet, AccessControlSetBuilder},
        op::{DnsRequestOptions, DnsResponse, Message, Query},
        rr::{
            Name, RData,
            RData::CNAME,
            Record, RecordType,
            rdata::{A, AAAA, NS},
        },
    },
};

#[derive(Clone)]
pub(crate) struct RecursorDnsHandle<P: ConnectionProvider> {
    roots: NameServerPool<P>,
    name_server_cache: MokaCache<Name, NameServerPool<P>>,
    local_root_delegations: Arc<HashMap<Name, RootZoneDelegation>>,
    response_cache: ResponseCache,
    #[cfg(feature = "metrics")]
    pub(super) metrics: RecursorMetrics,
    recursion_limit: u8,
    ns_recursion_limit: u8,
    prefer_tls_min_depth: Option<u8>,
    name_server_filter: AccessControlSet,
    pool_context: Arc<PoolContext>,
    conn_provider: P,
    connection_cache: MokaCache<IpAddr, Arc<NameServer<P>>>,
    transient_ns_error_cache: MokaCache<Query, Instant>,
    request_options: DnsRequestOptions,
    ttl_config: TtlConfig,
}

impl<P: ConnectionProvider> RecursorDnsHandle<P> {
    pub(super) fn new(
        roots: &[IpAddr],
        dnssec_policy: DnssecPolicy,
        encrypted_transport_state: Option<NameServerTransportState>,
        options: RecursorOptions,
        tls: TlsConfig,
        conn_provider: P,
        local_root_delegations: RootZoneDelegations,
    ) -> Result<Self, RecursorError> {
        assert!(!roots.is_empty(), "roots must not be empty");
        let servers = roots
            .iter()
            .copied()
            .map(|ip| {
                name_server_config(
                    ip,
                    None,
                    &options.opportunistic_encryption,
                    effective_prefer_tls(
                        options.prefer_tls,
                        options.prefer_tls_min_depth,
                        &Name::root(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        let RecursorOptions {
            ns_cache_size,
            response_cache_size,
            recursion_limit,
            ns_recursion_limit,
            allow_answers,
            deny_answers,
            allow_server,
            deny_server,
            avoid_local_udp_ports,
            cache_policy,
            case_randomization,
            num_concurrent_reqs,
            connection_timeout,
            happy_eyeballs_delay,
            transport_encryption: _,
            prefer_tls,
            prefer_tls_min_depth,
            insecure: _,
            tls_ca: _,
            tls_ca_directory: _,
            opportunistic_encryption,
            edns_payload_len,
        } = options;

        let avoid_local_udp_ports = Arc::new(avoid_local_udp_ports);

        debug!(
            "Using cache sizes {}/{}",
            ns_cache_size, response_cache_size
        );

        let mut pool_context = PoolContext::new(
            recursor_opts(
                avoid_local_udp_ports.clone(),
                case_randomization,
                edns_payload_len,
                num_concurrent_reqs,
                prefer_tls,
                connection_timeout,
                happy_eyeballs_delay,
            ),
            tls,
        )
        .with_probe_budget(
            opportunistic_encryption
                .max_concurrent_probes()
                .unwrap_or_default(),
        )
        .with_answer_filter(
            AccessControlSetBuilder::new("answers")
                .allow(allow_answers.iter()) // no recommended exceptions
                .deny(deny_answers.iter()) // no recommend default filters
                .build()?,
        );
        pool_context.opportunistic_encryption = opportunistic_encryption;
        if let Some(state) = encrypted_transport_state {
            pool_context = pool_context.with_transport_state(state);
        }

        let pool_context = Arc::new(pool_context);
        let roots =
            NameServerPool::from_config(servers, pool_context.clone(), conn_provider.clone());

        let name_server_cache = MokaCache::new(ns_cache_size as u64);
        let response_cache = ResponseCache::new(response_cache_size, cache_policy.clone());

        // DnsRequestOptions to use with outbound requests made by the recursor.
        let mut request_options = DnsRequestOptions::default();
        request_options.edns_set_dnssec_ok = dnssec_policy.is_security_aware();
        // Set RD=0 in queries made by the recursive resolver. See the last figure in
        // section 2.2 of RFC 1035, for example. Failure to do so may allow for loops
        // between recursive resolvers following referrals to each other.
        request_options.recursion_desired = false;
        request_options.edns_payload_len = edns_payload_len;

        Ok(Self {
            roots,
            name_server_cache,
            local_root_delegations: Arc::new(local_root_delegations.zones),
            response_cache,
            #[cfg(feature = "metrics")]
            metrics: RecursorMetrics::new(),
            recursion_limit,
            ns_recursion_limit,
            prefer_tls_min_depth,
            name_server_filter: AccessControlSetBuilder::new("name_servers")
                .allow(allow_server.iter())
                .deny(deny_server.iter())
                .build()?,
            pool_context,
            conn_provider,
            connection_cache: MokaCache::new(ns_cache_size as u64),
            transient_ns_error_cache: MokaCache::new(ns_cache_size as u64),
            request_options,
            ttl_config: cache_policy.clone(),
        })
    }

    fn effective_prefer_tls(&self, zone: &Name) -> bool {
        effective_prefer_tls(
            self.pool_context.options.prefer_tls,
            self.prefer_tls_min_depth,
            zone,
        )
    }

    pub(crate) async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
        depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, RecursorError> {
        #[cfg(feature = "metrics")]
        let _guard = self.metrics.new_inflight_query();

        if let Some(result) = self.response_cache.get(&query, request_time) {
            let response = result?;
            if response.authoritative {
                #[cfg(feature = "metrics")]
                {
                    self.metrics.cache_hit_counter.increment(1);
                    self.metrics
                        .cache_size
                        .set(self.response_cache.entry_count() as f64);
                }

                let response = self
                    .resolve_cnames(
                        response,
                        query.clone(),
                        request_time,
                        query_has_dnssec_ok,
                        depth,
                        cname_limit,
                    )
                    .await?;

                let result = response.maybe_strip_dnssec_records(query_has_dnssec_ok);
                #[cfg(feature = "metrics")]
                {
                    self.metrics
                        .cache_hit_duration
                        .record(request_time.elapsed());
                    self.metrics
                        .cache_size
                        .set(self.response_cache.entry_count() as f64);
                }
                return Ok(result);
            }
        }

        #[cfg(feature = "metrics")]
        self.metrics.cache_miss_counter.increment(1);

        // Recursively search for authoritative name servers for the queried record to build an NS
        // pool to use for queries for a given zone. By searching for the query name, (e.g.
        // 'www.example.com') we should end up with the following set of queries:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        // query NS example.com. for www.example.com. -> no data.
        //
        // ns_pool_for_name would then return an NS pool based the results of the last NS RRset,
        // plus any additional glue records that needed to be resolved, and the authoritative name
        // servers for example.com can be queried directly for 'www.example.com'.
        //
        // When querying zone.name() using this algorithm, you make an NS query for www.example.com
        // directed to the nameservers for example.com, which will generally result in those servers
        // returning a no data response, and an additional query being made for whatever record is
        // being queried.
        //
        // If the user is directly querying the second-level domain (e.g., an A query for example.com),
        // the following behavior will occur:
        //
        // query NS . for com. -> NS list + glue for com.
        // query NS com. for example.com. -> NS list + glue for example.com.
        //
        // ns_pool_for_name would return that as the NS pool to use for the query 'example.com'.
        // The subsequent lookup request for then ask the example.com. servers to resolve
        // A example.com.

        let zone = match query.query_type() {
            RecordType::DS => query.name().base_name(),
            _ => query.name().clone(),
        };

        let (depth, ns) = match self
            .ns_pool_for_name(zone.clone(), request_time, depth)
            .await
        {
            Ok((depth, ns)) => (depth, ns),
            // Handle the short circuit case for when we receive NXDOMAIN on a parent name, per RFC
            // 8020.
            Err(e) if e.is_nx_domain() => return Err(e),
            Err(e) => {
                return Err(RecursorError::from(format!(
                    "no nameserver found for {zone}: {e}"
                )));
            }
        };

        // Set the zone based on the longest delegation found by ns_pool_for_name.  This will
        // affect bailiwick filtering.
        let Some(zone) = ns.zone() else {
            return Err("no zone information in name server pool".into());
        };

        debug!(%zone, %query, "found zone for query");

        let cached_response = self.filtered_cache_lookup(&query, request_time);
        let response = match cached_response {
            Some(result) => result?,
            None => {
                self.lookup(query.clone(), zone.clone(), ns, request_time)
                    .await?
            }
        };

        let response = self
            .resolve_cnames(
                response,
                query.clone(),
                request_time,
                query_has_dnssec_ok,
                depth,
                cname_limit,
            )
            .await?;

        // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC records unless
        // explicitly requested
        let response = response.maybe_strip_dnssec_records(query_has_dnssec_ok);
        #[cfg(feature = "metrics")]
        {
            self.metrics
                .cache_miss_duration
                .record(request_time.elapsed());
            self.metrics
                .cache_size
                .set(self.response_cache.entry_count() as f64);
        }
        Ok(response)
    }

    pub(crate) fn pool_context(&self) -> &Arc<PoolContext> {
        &self.pool_context
    }

    /// Handle CNAME expansion for the current query
    #[async_recursion]
    async fn resolve_cnames(
        &self,
        mut response: Message,
        query: Query,
        now: Instant,
        query_has_dnssec_ok: bool,
        mut depth: u8,
        cname_limit: Arc<AtomicU8>,
    ) -> Result<Message, RecursorError> {
        let query_type = query.query_type();

        // Don't resolve CNAME lookups for a CNAME (or ANY) query
        if query_type == RecordType::CNAME || query_type == RecordType::ANY {
            return Ok(response);
        }

        // Return early if there aren't any CNAME in the response.
        let has_cname = response
            .all_sections()
            .any(|rec| matches!(rec.data, CNAME(_)));
        if !has_cname {
            return Ok(response);
        }

        depth += 1;
        RecursorError::recursion_exceeded(self.recursion_limit, depth, query.name())?;

        let mut cname_chain = vec![];

        for rec in response.all_sections() {
            let CNAME(name) = &rec.data else {
                continue;
            };

            // Check if the response has data for the canonical name.
            if response.answers.iter().any(|record| record.name == name.0) {
                continue;
            }

            let cname_query = Query::query(name.0.clone(), query_type);

            let count = cname_limit.fetch_add(1, Ordering::Relaxed) + 1;
            if count > MAX_CNAME_LOOKUPS {
                warn!("cname limit exceeded for query {query}");
                return Err(RecursorError::MaxRecordLimitExceeded {
                    count: count as usize,
                    record_type: RecordType::CNAME,
                });
            }

            // Note that we aren't worried about whether the intermediates are local or remote
            // to the original queried name, or included or not included in the original
            // response.  Resolve will either pull the intermediates out of the cache or query
            // the appropriate nameservers if necessary.
            let response = match self
                .resolve(
                    cname_query,
                    now,
                    query_has_dnssec_ok,
                    depth,
                    cname_limit.clone(),
                )
                .await
            {
                Ok(cname_r) => cname_r,
                Err(e) => {
                    return Err(e);
                }
            };

            // Here, we're looking for either the terminal record type (matching the
            // original query, or another CNAME.
            cname_chain.extend(response.answers.iter().filter_map(|r| {
                if r.record_type() == query_type || r.record_type() == RecordType::CNAME {
                    return Some(r.to_owned());
                }

                #[cfg(feature = "__dnssec")]
                if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &r.data {
                    let type_covered = rrsig.input().type_covered;
                    if type_covered == query_type || type_covered == RecordType::CNAME {
                        return Some(r.to_owned());
                    }
                }

                None
            }));
        }

        if !cname_chain.is_empty() {
            response.answers.extend(cname_chain);
        }

        Ok(response)
    }

    /// Retrieve a response from the cache, filtering out non-authoritative responses.
    fn filtered_cache_lookup(
        &self,
        query: &Query,
        now: Instant,
    ) -> Option<Result<Message, RecursorError>> {
        let response = match self.response_cache.get(query, now) {
            Some(Ok(response)) => response,
            Some(Err(e)) => return Some(Err(e.into())),
            None => return None,
        };

        if !response.authoritative {
            return None;
        }

        debug!(?response, "cached data");
        Some(Ok(response))
    }

    async fn lookup(
        &self,
        query: Query,
        zone: Name,
        ns: NameServerPool<P>,
        now: Instant,
    ) -> Result<Message, RecursorError> {
        let mut response = ns.lookup(query.clone(), self.request_options);

        #[cfg(feature = "metrics")]
        self.metrics.outgoing_query_counter.increment(1);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        let mut response = match response.next().await {
            Some(Ok(r)) => r,
            Some(Err(error)) => {
                debug!(?query, %error, "lookup error");
                self.response_cache.insert(query, Err(error.clone()), now);
                return Err(RecursorError::from(error));
            }
            None => {
                warn!("no response to lookup for {query}");
                return Err("no response to lookup".into());
            }
        };

        let answer_filter = |record: &Record| {
            if !is_subzone(&zone, &record.name) {
                debug!(
                    %record, %zone,
                    "dropping out of bailiwick record",
                );
                return false;
            }

            true
        };

        let answers_len = response.answers.len();
        let authorities_len = response.authorities.len();

        response.additionals.retain(answer_filter);
        response.answers.retain(answer_filter);
        response.authorities.retain(answer_filter);

        // If we stripped all of the answers out, or if we stripped all of the authorities
        // out and there are no answers, return an NXDomain response.
        if response.answers.is_empty() && answers_len != 0
            || (response.answers.is_empty()
                && response.authorities.is_empty()
                && authorities_len != 0)
        {
            return Err(RecursorError::Negative(AuthorityData::new(
                Box::new(query),
                None,
                false,
                true,
                None,
            )));
        }

        let message = response.into_message();
        self.response_cache.insert(query, Ok(message.clone()), now);
        Ok(message)
    }

    /// Identify the correct NameServerPool to use to answer queries for a given name.
    #[async_recursion]
    pub(crate) async fn ns_pool_for_name(
        &self,
        query_name: Name,
        request_time: Instant,
        mut depth: u8,
    ) -> Result<(u8, NameServerPool<P>), RecursorError> {
        // Iterate through zones from TLD down to the query name (not including root)
        let num_labels = query_name.num_labels();
        trace!(num_labels, %query_name, "looking for zones");

        let mut nameserver_pool = self.roots.clone().with_zone(Name::root());

        for i in 1..=num_labels {
            let zone = query_name.trim_to(i as usize);
            if let Some(ns) = self.name_server_cache.get(&zone) {
                match ns.ttl_expired() {
                    true => debug!(?zone, "cached name server pool expired"),
                    false => {
                        debug!(?zone, "already have cached name server pool for zone");
                        nameserver_pool = ns;
                        continue;
                    }
                }
            };

            let parent_zone = zone.base_name();
            let (positive_min_ttl, positive_max_ttl) = self
                .ttl_config
                .positive_response_ttl_bounds(RecordType::NS)
                .into_inner();

            if parent_zone.is_root() {
                if let Some(RootZoneDelegation { ips, ttl }) =
                    self.local_root_delegations.get(&zone)
                {
                    let mut config_group = Vec::new();
                    for ip in ips.iter().copied() {
                        if self.name_server_filter.denied(ip) {
                            debug!(
                                %ip,
                                "ignoring local root delegation address due to do_not_query"
                            );
                            continue;
                        }

                        config_group.push(name_server_config(
                            ip,
                            None,
                            &self.pool_context.opportunistic_encryption,
                            self.effective_prefer_tls(&zone),
                        ));
                    }

                    if !config_group.is_empty() {
                        let servers = self.name_servers_from_configs(&config_group);
                        let ns_pool_ttl = Duration::from_secs(*ttl as u64)
                            .clamp(positive_min_ttl, positive_max_ttl);

                        nameserver_pool =
                            NameServerPool::from_nameservers(servers, self.pool_context.clone())
                                .with_ttl(ns_pool_ttl)
                                .with_zone(zone.clone());

                        debug!(?zone, "using local root-zone delegation");
                        self.name_server_cache
                            .insert(zone.clone(), nameserver_pool.clone());
                        continue;
                    }
                }
            }

            trace!(depth, ?zone, "ns_pool_for_name: depth {depth} for {zone}");
            depth += 1;
            RecursorError::recursion_exceeded(self.ns_recursion_limit, depth, &zone)?;

            let query = Query::query(zone.clone(), RecordType::NS);

            // Query for nameserver records via the pool for the parent zone.
            let lookup_res = match self.response_cache.get(&query, request_time) {
                Some(Ok(response)) => {
                    debug!(?response, "cached data");
                    Ok(response)
                }
                Some(Err(e)) => Err(e.into()),
                None => {
                    self.lookup(query, parent_zone, nameserver_pool.clone(), request_time)
                        .await
                }
            };

            let response = match lookup_res {
                Ok(response) => response,
                // Short-circuit on NXDOMAIN, per RFC 8020.
                Err(e) if e.is_nx_domain() => return Err(e),
                // Short-circuit on timeouts. Requesting a longer name from the same pool would likely
                // encounter them again.
                Err(e) if e.is_timeout() => return Err(e),
                // The name `zone` is not a zone cut. Return the same pool of name servers again, but do
                // not cache it. If this was recursively called by `ns_pool_for_name()`, the outer call
                // will try again with one more label added to the iterative query name.
                Err(_) => {
                    trace!(?zone, "no zone cut at zone");
                    continue;
                }
            };

            // get all the NS records and glue
            let mut config_group = Vec::new();
            let mut need_ips_for_names = Vec::new();
            let mut glue_ips = HashMap::new();
            let mut has_zone_cut = false;
            let mut ns_pool_ttl = u32::MAX;

            let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());

            if ttl < ns_pool_ttl {
                ns_pool_ttl = ttl;
            }

            for zns in response.answers.iter().chain(response.authorities.iter()) {
                let RData::NS(ns_data) = &zns.data else {
                    continue;
                };

                if zns.name != zone {
                    trace!(
                        zone = %zone,
                        delegation_owner = %zns.name,
                        "ignoring NS RRset that does not match current zone-cut candidate"
                    );
                    continue;
                }
                has_zone_cut = true;

                if !is_subzone(&zone.base_name(), &zns.name) {
                    debug!(
                        name = ?zns.name,
                        parent = ?zone.base_name(),
                        "dropping out of bailiwick record",
                    );
                    continue;
                }

                if zns.ttl < ns_pool_ttl {
                    ns_pool_ttl = zns.ttl;
                }

                for record_type in [RecordType::A, RecordType::AAAA] {
                    if let Some(Ok(response)) = self
                        .response_cache
                        .get(&Query::query(ns_data.0.clone(), record_type), request_time)
                    {
                        let ttl = self.add_glue_to_map(&mut glue_ips, response.all_sections());
                        if ttl < ns_pool_ttl {
                            ns_pool_ttl = ttl;
                        }
                    }
                }

                match glue_ips.get(&ns_data.0) {
                    Some(glue) if !glue.is_empty() => {
                        config_group.extend(glue.iter().copied().map(|ip| {
                            name_server_config(
                                ip,
                                Some(&ns_data.0),
                                &self.pool_context.opportunistic_encryption,
                                self.effective_prefer_tls(&zone),
                            )
                        }));
                    }
                    _ => {
                        debug!(name_server = ?ns_data, "glue not found for name server");
                        need_ips_for_names.push(ns_data.to_owned());
                    }
                }
            }

            if !has_zone_cut {
                // Not a zone cut at this exact name. Keep the current pool and continue with
                // the next longer candidate zone.
                trace!(?zone, "no zone cut at zone");
                continue;
            }

            // If we have no glue, collect missing nameserver IP addresses.
            // For non-child name servers, get a new pool by calling ns_pool_for_name recursively.
            // For child child name servers, we can use the existing pool, but we *must* use lookup
            // to avoid infinite recursion.
            if config_group.is_empty() && !need_ips_for_names.is_empty() {
                debug!(?zone, "need glue for zone");

                let ttl;
                (ttl, depth) = self
                    .append_ips_from_lookup(
                        &zone,
                        depth,
                        request_time,
                        nameserver_pool.clone(),
                        need_ips_for_names.iter(),
                        &mut config_group,
                    )
                    .await?;

                if ttl < ns_pool_ttl {
                    ns_pool_ttl = ttl;
                }
            }

            let servers = self.name_servers_from_configs(&config_group);

            let ns_pool_ttl =
                Duration::from_secs(ns_pool_ttl as u64).clamp(positive_min_ttl, positive_max_ttl);

            nameserver_pool = NameServerPool::from_nameservers(servers, self.pool_context.clone())
                .with_ttl(ns_pool_ttl)
                .with_zone(zone.clone());

            // store in cache for future usage
            debug!(?zone, "found nameservers for {zone}");
            self.name_server_cache
                .insert(zone.clone(), nameserver_pool.clone());
        }

        #[cfg(feature = "metrics")]
        {
            self.metrics
                .name_server_cache_size
                .set(self.name_server_cache.entry_count() as f64);
            self.metrics
                .connection_cache_size
                .set(self.connection_cache.entry_count() as f64);
        }

        Ok((depth, nameserver_pool))
    }

    /// Helper function to add IP addresses from any A or AAAA records to a map indexed by record
    /// name.
    fn add_glue_to_map<'a>(
        &self,
        glue_map: &mut HashMap<Name, Vec<IpAddr>>,
        records: impl Iterator<Item = &'a Record>,
    ) -> u32 {
        let mut ttl = u32::MAX;

        for record in records {
            let ip = match &record.data {
                RData::A(A(ipv4)) => (*ipv4).into(),
                RData::AAAA(AAAA(ipv6)) => (*ipv6).into(),
                _ => continue,
            };
            if self.name_server_filter.denied(ip) {
                debug!(name = %record.name, %ip, "ignoring address due to do_not_query");
                continue;
            }
            if record.ttl < ttl {
                ttl = record.ttl;
            }
            let ns_glue_ips = match glue_map.get_mut(&record.name) {
                Some(ips) => ips,
                None => {
                    glue_map.insert(record.name.clone(), Vec::new());
                    glue_map.get_mut(&record.name).unwrap()
                }
            };
            if !ns_glue_ips.contains(&ip) {
                ns_glue_ips.push(ip);
            }
        }

        ttl
    }

    async fn append_ips_from_lookup<'a, I: Iterator<Item = &'a NS>>(
        &self,
        zone: &Name,
        depth: u8,
        request_time: Instant,
        nameserver_pool: NameServerPool<P>,
        nameservers: I,
        config: &mut Vec<NameServerConfig>,
    ) -> Result<(u32, u8), RecursorError> {
        let mut pool_queries = vec![];
        let mut last_error: Option<RecursorError> = None;
        let nameservers = nameservers.map(|ns| ns.0.clone()).collect::<Vec<_>>();
        let num_concurrent_reqs = self.pool_context.options.num_concurrent_reqs;

        let mut ns_pool_lookups = stream::iter(nameservers.into_iter().map(|record_name| {
            let zone = zone.clone();
            let nameserver_pool = nameserver_pool.clone();
            async move {
                if is_subzone(&zone, &record_name) {
                    return (record_name, None, Ok(Some(nameserver_pool)));
                }

                // For non-child nameservers, find a pool for the nameserver's own zone. Skip
                // repeated transient failures for the configured negative TTL window.
                let ns_query = Query::query(record_name.clone(), RecordType::NS);
                if self.transient_ns_error_cached(&ns_query, request_time) {
                    return (record_name, Some(ns_query), Ok(None));
                }

                let result = self
                    .ns_pool_for_name(record_name.clone(), request_time, depth)
                    .await
                    .map(|(_, pool)| Some(pool.with_zone(zone)))
                    .inspect_err(|e| {
                        if Self::is_transient_recursor_error(e) {
                            self.cache_transient_ns_error(ns_query.clone(), request_time);
                        }
                    });

                (record_name, Some(ns_query), result)
            }
        }))
        .buffer_unordered(num_concurrent_reqs);

        while let Some((record_name, ns_query, result)) = ns_pool_lookups.next().await {
            match result {
                Ok(Some(pool)) => {
                    if let Some(query) = ns_query.as_ref() {
                        self.clear_transient_ns_error(query);
                    }
                    pool_queries.push((pool, record_name));
                }
                Ok(None) => {
                    debug!(
                        name_server = %record_name,
                        "skipping nameserver due to cached transient lookup failure"
                    );
                }
                Err(error) => {
                    warn!(
                        name_server = %record_name,
                        %error,
                        "append_ips_from_lookup: nameserver pool resolution failed"
                    );
                    last_error = Some(error);
                }
            }
        }

        let mut lookup_queries = Vec::new();
        for (pool, query_name) in pool_queries {
            for record_type in [RecordType::A, RecordType::AAAA] {
                lookup_queries.push((pool.clone(), Query::query(query_name.clone(), record_type)));
            }
        }

        let mut futures = stream::iter(lookup_queries.into_iter())
            .map(|(pool, query)| async move {
                if self.transient_ns_error_cached(&query, request_time) {
                    return (query, Ok::<Option<DnsResponse>, NetError>(None));
                }

                let (response, _rest) = pool
                    .lookup(query.clone(), self.request_options)
                    .into_future()
                    .await;
                let response = match response {
                    Some(Ok(response)) => Ok(Some(response)),
                    Some(Err(error)) => Err(error),
                    None => Err(NetError::from("no response to lookup")),
                };

                (query, response)
            })
            .buffer_unordered(num_concurrent_reqs);

        let mut ttl = u32::MAX;

        while let Some((query, next)) = futures.next().await {
            match next {
                Ok(Some(response)) => {
                    self.clear_transient_ns_error(&query);
                    debug!("append_ips_from_lookup: A or AAAA response: {response:?}");
                    let ns_name = query.name().clone();
                    let msg = response.into_message();
                    self.response_cache
                        .insert(query, Ok(msg.clone()), request_time);
                    config.extend(msg.answers
                        .into_iter()
                        .filter_map(|answer| {
                            let ip = answer.data.ip_addr()?;

                            if self.name_server_filter.denied(ip) {
                                debug!(%ip, "append_ips_from_lookup: ignoring address due to do_not_query");
                                None
                            } else {
                                if answer.ttl < ttl {
                                    ttl = answer.ttl;
                                }
                                Some(ip)
                            }
                        })
                        .map(|ip| {
                            name_server_config(
                                ip,
                                Some(&ns_name),
                                &self.pool_context.opportunistic_encryption,
                                self.effective_prefer_tls(zone),
                            )
                        }));
                }
                Ok(None) => {
                    debug!(%query, "append_ips_from_lookup: skipping cached transient error");
                }
                Err(e) => {
                    if matches!(e, NetError::Dns(crate::net::DnsError::NoRecordsFound(_)))
                        && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
                    {
                        debug!(
                            %query,
                            "append_ips_from_lookup: no A/AAAA records for nameserver name"
                        );
                        continue;
                    }

                    if Self::is_transient_net_error(&e) {
                        self.cache_transient_ns_error(query, request_time);
                    }
                    let error = RecursorError::from(e.clone());
                    last_error = Some(error);
                    warn!("append_ips_from_lookup: resolution failed failed: {e}");
                }
            }
        }

        if config.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                RecursorError::from("failed to resolve address records for delegated nameservers")
            }));
        }

        Ok((ttl, depth))
    }

    fn transient_ns_error_cached(&self, query: &Query, now: Instant) -> bool {
        match self.transient_ns_error_cache.get(query) {
            Some(valid_until) if valid_until > now => true,
            Some(_) => {
                self.transient_ns_error_cache.invalidate(query);
                false
            }
            None => false,
        }
    }

    fn clear_transient_ns_error(&self, query: &Query) {
        self.transient_ns_error_cache.invalidate(query);
    }

    fn cache_transient_ns_error(&self, query: Query, now: Instant) {
        let (negative_min_ttl, _) = self
            .ttl_config
            .negative_response_ttl_bounds(RecordType::NS)
            .into_inner();
        let ttl = negative_min_ttl.max(Duration::from_secs(1));

        self.transient_ns_error_cache.insert(query, now + ttl);
    }

    fn is_transient_recursor_error(error: &RecursorError) -> bool {
        match error {
            RecursorError::Timeout => true,
            RecursorError::Net(net) => Self::is_transient_net_error(net),
            _ => false,
        }
    }

    fn is_transient_net_error(error: &NetError) -> bool {
        matches!(
            error,
            NetError::Timeout | NetError::NoConnections | NetError::Busy | NetError::Io(_)
        )
    }

    fn name_servers_from_configs(
        &self,
        config_group: &[NameServerConfig],
    ) -> Vec<Arc<NameServer<P>>> {
        config_group
            .iter()
            .map(|server| {
                if let Some(ns) = self.connection_cache.get(&server.ip) {
                    return ns;
                }

                debug!(?server, "adding new name server to cache");
                let ns = Arc::new(NameServer::new(
                    [],
                    server.clone(),
                    &self.pool_context.clone().options,
                    self.conn_provider.clone(),
                ));
                self.connection_cache.insert(server.ip, ns.clone());
                ns
            })
            .collect()
    }
}

#[cfg(feature = "__dnssec")]
mod for_dnssec {
    use futures_util::{
        future,
        stream::{self, BoxStream},
    };

    use super::*;
    use crate::{
        net::{DnsHandle, NetError},
        proto::op::{DnsRequest, DnsResponse, OpCode},
    };

    impl<P: ConnectionProvider> DnsHandle for RecursorDnsHandle<P> {
        type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
        type Runtime = P::RuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            let query = if let OpCode::Query = request.op_code {
                if let Some(query) = request.queries.first().cloned() {
                    query
                } else {
                    return Box::pin(stream::once(future::err(NetError::from(
                        "no query in request",
                    ))));
                }
            } else {
                return Box::pin(stream::once(future::err(NetError::from(
                    "request is not a query",
                ))));
            };

            let this = self.clone();
            stream::once(async move {
                // request the DNSSEC records; we'll strip them if not needed on the caller side
                let do_bit = true;

                let future =
                    this.resolve(query, Instant::now(), do_bit, 0, Arc::new(AtomicU8::new(0)));
                let response = match future.await {
                    Ok(response) => response,
                    Err(e) => return Err(NetError::from(e)),
                };

                // `DnssecDnsHandle` will only look at the answer section of the message so
                // we can put "stubs" in the other fields
                let mut msg = Message::query();

                msg.add_answers(response.answers.iter().cloned());
                msg.add_authorities(response.authorities.iter().cloned());
                msg.add_additionals(response.additionals.iter().cloned());

                DnsResponse::from_message(msg.into_response()).map_err(NetError::from)
            })
            .boxed()
        }
    }
}

fn recursor_opts(
    avoid_local_udp_ports: Arc<HashSet<u16>>,
    case_randomization: bool,
    edns_payload_len: u16,
    num_concurrent_reqs: usize,
    prefer_tls: bool,
    connection_timeout: Option<Duration>,
    happy_eyeballs_delay: Option<Duration>,
) -> ResolverOpts {
    let default = ResolverOpts::default();
    ResolverOpts {
        ndots: 0,
        edns0: true,
        #[cfg(feature = "__dnssec")]
        validate: false, // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
        preserve_intermediates: true,
        recursion_desired: false,
        num_concurrent_reqs: Ord::max(num_concurrent_reqs, 1),
        avoid_local_udp_ports,
        case_randomization,
        edns_payload_len,
        prefer_tls,
        timeout: connection_timeout.unwrap_or(default.timeout),
        happy_eyeballs_delay,
        ..default
    }
}

fn name_server_config(
    ip: IpAddr,
    ns_name: Option<&Name>,
    opportunistic_encryption: &OpportunisticEncryption,
    prefer_tls: bool,
) -> NameServerConfig {
    #[cfg(feature = "__tls")]
    if prefer_tls {
        let server_name = tls_server_name(ip, ns_name);
        return NameServerConfig::new(
            ip,
            true,
            vec![
                ConnectionConfig::tls(server_name),
                ConnectionConfig::udp(),
                ConnectionConfig::tcp(),
            ],
        );
    }

    #[cfg(not(feature = "__tls"))]
    {
        let _ = prefer_tls;
        let _ = ns_name;
    }

    match opportunistic_encryption {
        #[cfg(any(
            feature = "tls-aws-lc-rs",
            feature = "tls-ring",
            feature = "quic-aws-lc-rs",
            feature = "quic-ring"
        ))]
        OpportunisticEncryption::Enabled { .. } => NameServerConfig::opportunistic_encryption(ip),
        _ => NameServerConfig::udp_and_tcp(ip),
    }
}

#[cfg(feature = "__tls")]
fn tls_server_name(ip: IpAddr, ns_name: Option<&Name>) -> Arc<str> {
    if let Some(name) = ns_name {
        let fqdn = name.to_ascii();
        if let Some(stripped) = fqdn.strip_suffix('.') {
            if !stripped.is_empty() {
                return Arc::from(stripped);
            }
        }
    }

    Arc::from(ip.to_string())
}

/// Returns whether TLS should be preferred for a nameserver at the given zone.
///
/// When `min_depth` is set, TLS is preferred only for zones with at least that many labels
/// (e.g. `min_depth = 2` skips TLS for root `.` and TLD `com.` servers).
fn effective_prefer_tls(prefer_tls: bool, min_depth: Option<u8>, zone: &Name) -> bool {
    if !prefer_tls {
        return false;
    }
    min_depth.is_none_or(|min| zone.num_labels() >= min)
}

/// Maximum number of cname records to look up in a CNAME chain, regardless of the recursion
/// depth limit
const MAX_CNAME_LOOKUPS: u8 = 64;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(feature = "__tls")]
    use crate::proto::rr::Name;
    use ipnet::IpNet;

    use crate::{
        net::runtime::TokioRuntimeProvider,
        recursor::{DnssecPolicy, Recursor, RecursorMode, RecursorOptions},
    };

    #[test]
    fn test_nameserver_filter() {
        let options = RecursorOptions {
            allow_server: [IpNet::new(IpAddr::from([192, 168, 0, 1]), 32).unwrap()].to_vec(),
            deny_server: [
                IpNet::new(IpAddr::from(Ipv4Addr::LOCALHOST), 8).unwrap(),
                IpNet::new(IpAddr::from([192, 168, 0, 0]), 23).unwrap(),
                IpNet::new(IpAddr::from([172, 17, 0, 0]), 20).unwrap(),
            ]
            .to_vec(),
            ..RecursorOptions::default()
        };

        #[cfg_attr(not(feature = "__dnssec"), allow(irrefutable_let_patterns))]
        let Recursor {
            mode: RecursorMode::NonValidating { handle },
        } = Recursor::new(
            &[IpAddr::from([192, 0, 2, 1])],
            DnssecPolicy::default(),
            None,
            options,
            TokioRuntimeProvider::default(),
        )
        .unwrap()
        else {
            panic!("unexpected DNSSEC validation mode");
        };

        for addr in [
            [127, 0, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 1, 0],
            [192, 168, 1, 254],
            [172, 17, 0, 1],
        ] {
            assert!(handle.name_server_filter.denied(IpAddr::from(addr)));
        }

        for addr in [[128, 0, 0, 0], [192, 168, 2, 0], [192, 168, 0, 1]] {
            assert!(!handle.name_server_filter.denied(IpAddr::from(addr)));
        }
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn test_tls_server_name_prefers_ns_name() {
        let ns_name = Name::from_ascii("ns1.example.com.").expect("valid DNS name");
        let server_name = super::tls_server_name(IpAddr::from([192, 0, 2, 1]), Some(&ns_name));
        assert_eq!(&*server_name, "ns1.example.com");
    }

    #[cfg(feature = "__tls")]
    #[test]
    fn test_tls_server_name_falls_back_to_ip() {
        let server_name = super::tls_server_name(IpAddr::from([192, 0, 2, 1]), None);
        assert_eq!(&*server_name, "192.0.2.1");
    }
}
