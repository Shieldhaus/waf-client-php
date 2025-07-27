<?php

namespace NetFend\WAFClient;

/**
 * WAF Client SDK - Enhanced Version with Cached Configuration System (PHP)
 * Fetches and caches configurations from /v1/user/me endpoint
 * Converted from Node.js version with full configuration synchronization
 */

class WAFClient
{
    private array $config;
    private array $cache = [];
    private array $rateLimitMap = [];
    private ?array $configCache = null;
    private int $lastConfigFetch = 0;
    private int $configRefreshInterval;
    private int $configTimeout;

    public function __construct(array $options = [])
    {
        if (empty($options['apiKey'])) {
            throw new \InvalidArgumentException('WAF API Key is required');
        }

        $this->configRefreshInterval = $options['configRefreshInterval'] ?? 10000; // 10 seconds
        $this->configTimeout = $options['configTimeout'] ?? 5000;

        // Initialize fallback configuration
        $this->config = [
            'apiKey' => $options['apiKey'],
            'configEndpoint' => $options['configEndpoint'] ?? 'https://graphnet.emailsbit.com/waf/v1/user/me',
            'wafEndpoint' => $options['wafEndpoint'] ?? 'https://graphnet.emailsbit.com/waf/v1/validate',
            'timeout' => $options['timeout'] ?? 5000,
            'enabled' => $options['enabled'] ?? true,
            'blockOnError' => $options['blockOnError'] ?? true,
            'logRequests' => $options['logRequests'] ?? false,
            'responseType' => $options['responseType'] ?? 'rest',
            'onWafError' => $options['onWafError'] ?? 'allow',
            'protections' => [
                'xss' => ['enabled' => $options['protections']['xss']['enabled'] ?? true],
                'sqlInjection' => ['enabled' => $options['protections']['sqlInjection']['enabled'] ?? true],
                'rce' => ['enabled' => $options['protections']['rce']['enabled'] ?? true],
                'pathTraversal' => ['enabled' => $options['protections']['pathTraversal']['enabled'] ?? true],
                'maliciousHeaders' => ['enabled' => $options['protections']['maliciousHeaders']['enabled'] ?? true],
                'fileUpload' => ['enabled' => $options['protections']['fileUpload']['enabled'] ?? true],
                'ipCheck' => ['enabled' => $options['protections']['ipCheck']['enabled'] ?? true],
            ],
            'validatedMethods' => $options['validatedMethods'] ?? ['POST', 'PUT', 'PATCH', 'DELETE'],
            'ignoredPaths' => $options['ignoredPaths'] ?? ['/health'],
            'enableCache' => $options['enableCache'] ?? true,
            'cacheTimeout' => $options['cacheTimeout'] ?? 60000,
            'customHeaders' => $options['customHeaders'] ?? [],
        ];

        $this->configCache = $this->config; // Set fallback config initially
        $this->validateProtectionSettings();
        $this->initializeConfig();
        $this->startCacheCleaner();
    }

    private function initializeConfig(): void
    {
        try {
            $this->fetchConfiguration();
            $this->startConfigUpdateLoop();
        } catch (\Exception $error) {
            error_log("⚠️  [WAF Client] Failed to fetch initial configuration, using fallback: {$error->getMessage()}");
            $this->configCache = $this->config;
        }
    }

    private function fetchConfiguration(): array
    {
        try {
            $headers = [
                'Authorization: ' . $this->config['apiKey'],
                'Content-Type: application/json',
                'X-WAF-Client: php',
            ];

            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => implode("\r\n", $headers),
                    'timeout' => $this->configTimeout / 1000,
                    'ignore_errors' => true,
                ]
            ]);

            $response = file_get_contents($this->config['configEndpoint'], false, $context);
            
            if ($response === false) {
                throw new \Exception('Network error - unable to connect to config endpoint');
            }

            $responseData = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid JSON response from config endpoint');
            }

            if (!isset($responseData['success']) || !$responseData['success'] || !isset($responseData['wafSetting'])) {
                throw new \Exception('Config API returned invalid response: ' . ($responseData['message'] ?? 'Unknown error'));
            }

            $wafSetting = $responseData['wafSetting'];

            // Transform API response to internal config format
            $newConfig = [
                'apiKey' => $this->config['apiKey'],
                'configEndpoint' => $this->config['configEndpoint'],
                'wafEndpoint' => $this->config['wafEndpoint'],
                'enabled' => $wafSetting['enabled'] ?? $this->config['enabled'],
                'blockOnError' => $wafSetting['blockOnError'] ?? $this->config['blockOnError'],
                'logRequests' => $wafSetting['logRequests'] ?? $this->config['logRequests'],
                'responseType' => $wafSetting['responseType'] ?? $this->config['responseType'],
                'onWafError' => $wafSetting['onWafError'] ?? $this->config['onWafError'],
                'timeout' => $wafSetting['timeout'] ?? $this->config['timeout'],
                'cacheTimeout' => $wafSetting['cacheTimeout'] ?? $this->config['cacheTimeout'],
                'protections' => [
                    'xss' => ['enabled' => $wafSetting['protections']['xss']['enabled'] ?? $this->config['protections']['xss']['enabled']],
                    'sqlInjection' => ['enabled' => $wafSetting['protections']['sqlInjection']['enabled'] ?? $this->config['protections']['sqlInjection']['enabled']],
                    'rce' => ['enabled' => $wafSetting['protections']['rce']['enabled'] ?? $this->config['protections']['rce']['enabled']],
                    'pathTraversal' => ['enabled' => $wafSetting['protections']['pathTraversal']['enabled'] ?? $this->config['protections']['pathTraversal']['enabled']],
                    'maliciousHeaders' => ['enabled' => $wafSetting['protections']['maliciousHeaders']['enabled'] ?? $this->config['protections']['maliciousHeaders']['enabled']],
                    'fileUpload' => ['enabled' => $wafSetting['protections']['fileUpload']['enabled'] ?? $this->config['protections']['fileUpload']['enabled']],
                    'ipCheck' => ['enabled' => $wafSetting['protections']['ipCheck']['enabled'] ?? $this->config['protections']['ipCheck']['enabled']],
                ],
                'validatedMethods' => array_keys(array_filter(
                    $wafSetting['validatedMethods'] ?? array_combine($this->config['validatedMethods'], array_fill(0, count($this->config['validatedMethods']), true)),
                    fn($enabled) => $enabled
                )),
                'ignoredPaths' => $wafSetting['ignoredPaths'] ?? $this->config['ignoredPaths'],
                'configFetchedAt' => date('c'),
                'configUpdatedAt' => $wafSetting['updatedAt'] ?? date('c'),
                'enableCache' => $this->config['enableCache'],
                'customHeaders' => $this->config['customHeaders'],
            ];

            // Check if configuration changed
            $configChanged = !$this->configCache || json_encode($this->configCache) !== json_encode($newConfig);

            if ($configChanged) {
                $oldConfig = $this->configCache;
                $this->configCache = $newConfig;
                $this->lastConfigFetch = time() * 1000;

                if ($this->configCache['logRequests']) {
                    error_log('🔄 [WAF Client] Configuration updated: ' . json_encode([
                        'enabled' => $newConfig['enabled'],
                        'protections' => array_keys(array_filter($newConfig['protections'], fn($p) => $p['enabled'])),
                        'validatedMethods' => $newConfig['validatedMethods'],
                        'ignoredPaths' => count($newConfig['ignoredPaths']),
                        'responseType' => $newConfig['responseType'],
                        'updatedAt' => $newConfig['configUpdatedAt'],
                        'changed' => $oldConfig ? $this->getConfigChanges($oldConfig, $newConfig) : 'initial_load'
                    ]));

                    // Clear cache when configuration changes
                    if ($oldConfig && !empty($this->cache)) {
                        $this->cache = [];
                        error_log('🗑️  [WAF Client] Request cache cleared due to config change');
                    }
                }
            }

            return $newConfig;

        } catch (\Exception $error) {
            error_log('❌ [WAF Client] Failed to fetch configuration: ' . json_encode([
                'message' => $error->getMessage(),
                'endpoint' => $this->config['configEndpoint'],
                'isNetworkError' => true
            ]));

            // Use cached config if available, otherwise fallback
            if ($this->configCache) {
                if ($this->configCache['logRequests']) {
                    error_log('📋 [WAF Client] Using cached configuration due to fetch error');
                }
                return $this->configCache;
            }

            $this->configCache = $this->config;
            return $this->config;
        }
    }

    private function getConfigChanges(array $oldConfig, array $newConfig): array
    {
        $changes = [];

        if ($oldConfig['enabled'] !== $newConfig['enabled']) {
            $changes[] = "enabled: {$oldConfig['enabled']} → {$newConfig['enabled']}";
        }

        if ($oldConfig['responseType'] !== $newConfig['responseType']) {
            $changes[] = "responseType: {$oldConfig['responseType']} → {$newConfig['responseType']}";
        }

        foreach ($newConfig['protections'] as $protection => $config) {
            if ($oldConfig['protections'][$protection]['enabled'] !== $config['enabled']) {
                $changes[] = "$protection: {$oldConfig['protections'][$protection]['enabled']} → {$config['enabled']}";
            }
        }

        $oldMethods = implode(',', $oldConfig['validatedMethods']);
        $newMethods = implode(',', $newConfig['validatedMethods']);
        if ($oldMethods !== $newMethods) {
            $changes[] = "validatedMethods: [$oldMethods] → [$newMethods]";
        }

        return $changes ?: ['no_changes'];
    }

    private function startConfigUpdateLoop(): void
    {
        // PHP doesn't support persistent intervals like Node.js
        // We'll check config freshness in middleware instead
        if (isset($this->configCache['logRequests']) && $this->configCache['logRequests']) {
            $intervalSeconds = $this->configRefreshInterval / 1000;
            error_log("🔄 [WAF Client] Config refresh loop simulation started ({$intervalSeconds}s interval)");
        }
    }

    public function getCurrentConfig(): array
    {
        return $this->configCache ?? $this->config;
    }

    private function validateProtectionSettings(): void
    {
        $validProtections = ['xss', 'sqlInjection', 'rce', 'pathTraversal', 'maliciousHeaders', 'fileUpload', 'ipCheck'];

        foreach ($this->config['protections'] as $key => $value) {
            if (!in_array($key, $validProtections)) {
                error_log("⚠️  [WAF Client] Unknown protection type: {$key}. Valid types: " . implode(', ', $validProtections));
            }

            if (!is_bool($value['enabled'])) {
                error_log("⚠️  [WAF Client] Protection {$key}.enabled must be boolean, got " . gettype($value['enabled']));
                $this->config['protections'][$key]['enabled'] = true;
            }
        }
    }

    private function shouldIgnorePath(string $path): bool
    {
        $config = $this->getCurrentConfig();
        foreach ($config['ignoredPaths'] as $ignoredPath) {
            if (stripos($path, $ignoredPath) !== false) {
                return true;
            }
        }
        return false;
    }

    private function shouldValidateMethod(string $method): bool
    {
        $config = $this->getCurrentConfig();
        return in_array(strtoupper($method), $config['validatedMethods']);
    }

    private function createRequestHash(array $req): ?string
    {
        $config = $this->getCurrentConfig();
        if (!$config['enableCache']) {
            return null;
        }

        $data = [
            'method' => $req['method'],
            'path' => $req['path'] ?? $req['url'],
            'body' => $req['body'],
            'headers' => [
                'user-agent' => $req['headers']['User-Agent'] ?? '',
                'content-type' => $req['headers']['Content-Type'] ?? ''
            ],
            'protections' => $config['protections'],
            'configHash' => md5(json_encode($config))
        ];

        return md5(json_encode($data));
    }

    private function checkCache(?string $hash): ?array
    {
        $config = $this->getCurrentConfig();
        if (!$hash || !$config['enableCache'] || !isset($this->cache[$hash])) {
            return null;
        }

        $cached = $this->cache[$hash];
        if ((time() * 1000) - $cached['timestamp'] > $config['cacheTimeout']) {
            unset($this->cache[$hash]);
            return null;
        }

        return $cached['result'];
    }

    private function saveToCache(?string $hash, array $result): void
    {
        $config = $this->getCurrentConfig();
        if (!$hash || !$config['enableCache']) {
            return;
        }

        $this->cache[$hash] = [
            'result' => $result,
            'timestamp' => time() * 1000
        ];
    }

    public function startCacheCleaner(): void
    {
        // PHP cleanup handled in middleware
    }

    private function cleanupCache(): void
    {
        $config = $this->getCurrentConfig();
        $now = time() * 1000;

        foreach ($this->cache as $hash => $data) {
            if ($now - $data['timestamp'] > $config['cacheTimeout']) {
                unset($this->cache[$hash]);
            }
        }

        $rateLimitWindow = $config['rateLimitWindow'];
        foreach ($this->rateLimitMap as $ip => $requests) {
            $validRequests = array_filter($requests, fn($timestamp) => $now - $timestamp < $rateLimitWindow);
            if (empty($validRequests)) {
                unset($this->rateLimitMap[$ip]);
            } else {
                $this->rateLimitMap[$ip] = array_values($validRequests);
            }
        }
    }

    public function validateRequest(array $req): array
    {
        $config = $this->getCurrentConfig();

        try {
            $clientIp = $req['ip'] ?? $req['connection']['remoteAddress'] ?? 'unknown';

            $payload = [
                'method' => $req['method'],
                'path' => $req['path'] ?? $req['url'],
                'headers' => $req['headers'],
                'body' => $req['body'],
                'query' => $req['query'],
                'params' => $req['params'],
                'timestamp' => date('c'),
                'clientIp' => $clientIp,
                'userAgent' => $req['headers']['User-Agent'] ?? '',
                'protections' => $config['protections'],
                'clientInfo' => [
                    'apiKey' => $config['apiKey'],
                    'version' => '2.1.0',
                    'responseType' => $config['responseType'],
                    'configFetchedAt' => $config['configFetchedAt'] ?? date('c'),
                    'configUpdatedAt' => $config['configUpdatedAt'] ?? date('c')
                ]
            ];

            if ($config['logRequests']) {
                $enabledProtections = array_keys(array_filter($config['protections'], fn($p) => $p['enabled']));
                error_log('🔍 [WAF Client] Sending for validation: ' . json_encode([
                    'method' => $payload['method'],
                    'path' => $payload['path'],
                    'hasBody' => !empty($payload['body']),
                    'protections' => $enabledProtections,
                    'ip' => $clientIp,
                    'configAge' => isset($config['configFetchedAt']) ?
                        round((time() * 1000 - strtotime($config['configFetchedAt']) * 1000) / 1000) . 's' : 'unknown'
                ]));
            }

            $headers = array_merge([
                'Content-Type: application/json',
                'Authorization: ' . $config['apiKey'],
                'X-WAF-Client: php',
                'X-WAF-Response-Type: ' . $config['responseType'],
            ], array_map(fn($k, $v) => "$k: $v", array_keys($config['customHeaders']), $config['customHeaders']));

            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => implode("\r\n", $headers),
                    'content' => json_encode($payload),
                    'timeout' => $config['timeout'] / 1000,
                    'ignore_errors' => true
                ]
            ]);

            $response = file_get_contents($config['wafEndpoint'], false, $context);

            if ($response === false) {
                throw new \Exception('Network error - unable to connect');
            }

            $responseData = json_decode($response, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid JSON response');
            }

            if ($config['logRequests']) {
                $appliedProtections = isset($responseData['appliedProtections']) ?
                    array_keys(array_filter($responseData['appliedProtections'], fn($p) => $p['enabled'] ?? false)) : [];
                error_log('📨 [WAF Client] Server response: ' . json_encode([
                    'blocked' => $responseData['blocked'] ?? false,
                    'reason' => $responseData['reason'] ?? null,
                    'violations' => $responseData['validationResults']['totalViolations'] ?? 0,
                    'appliedProtections' => $appliedProtections
                ]));
            }

            return $responseData;

        } catch (\Exception $error) {
            if ($config['logRequests']) {
                error_log('❌ [WAF Client] Network/timeout error: ' . json_encode([
                    'message' => $error->getMessage(),
                    'isNetworkError' => true,
                    'timeout' => strpos($error->getMessage(), 'timeout') !== false
                ]));
            }

            if ($config['onWafError'] === 'block' || $config['blockOnError']) {
                return [
                    'allowed' => false,
                    'blocked' => true,
                    'reason' => 'WAF_NETWORK_ERROR',
                    'message' => 'Unable to connect to security service',
                    'error' => [
                        'type' => 'NETWORK_ERROR',
                        'timeout' => strpos($error->getMessage(), 'timeout') !== false
                    ]
                ];
            }

            return [
                'allowed' => true,
                'blocked' => false,
                'reason' => 'WAF_NETWORK_ERROR',
                'message' => 'Security validation unavailable, request allowed',
                'warning' => true
            ];
        }
    }

    public function createGraphQLErrorResponse(?array $operationInfo, array $validation): array
    {
        $toCamelCase = function($str) {
            if (!$str) return $str;
            return lcfirst(str_replace(' ', '', ucwords(str_replace('_', ' ', $str))));
        };

        $violationDetails = $validation['validationResults']['violations'] ?? [];
        $violationSummary = array_map(function($v) {
            return [
                'type' => $v['type'],
                'severity' => $v['severity'],
                'count' => is_array($v['details']) ? count($v['details']) : 1,
                'readableType' => str_replace(['_DETECTED', '_'], ['', ' '], $v['type'])
            ];
        }, $violationDetails);

        $violationList = implode(', ', array_map(function($v) {
            return str_replace(['_DETECTED', '_'], ['', ' '], $v['type']);
        }, $violationDetails));

        $enhancedMessage = $violationList ?
            ($validation['message'] ?? "Request blocked by security policy") . " ({$violationList})" :
            ($validation['message'] ?? "Request blocked by security policy");

        if (!$operationInfo) {
            return [
                'data' => null,
                'errors' => [
                    [
                        'message' => $enhancedMessage,
                        'extensions' => [
                            'code' => $validation['reason'] ?? "SECURITY_VIOLATION",
                            'blocked' => true,
                            'waf' => true,
                            'violations' => $violationSummary,
                            'violationTypes' => $violationList,
                            'totalViolations' => $validation['validationResults']['totalViolations'] ?? 0,
                            'highSeverityViolations' => $validation['validationResults']['highSeverityViolations'] ?? 0
                        ],
                    ],
                ],
            ];
        }

        $operationName = $toCamelCase($operationInfo['name']);
        $response = [
            'data' => [],
            'errors' => [
                [
                    'message' => $enhancedMessage,
                    'extensions' => [
                        'code' => $validation['reason'] ?? "SECURITY_VIOLATION",
                        'operation' => $operationName,
                        'blocked' => true,
                        'waf' => true,
                        'violations' => $violationSummary,
                        'violationTypes' => $violationList,
                        'totalViolations' => $validation['validationResults']['totalViolations'] ?? 0,
                        'highSeverityViolations' => $validation['validationResults']['highSeverityViolations'] ?? 0
                    ],
                ],
            ],
        ];

        $response['data'][$operationName] = [
            'success' => false,
            'message' => $enhancedMessage,
            'blocked' => true,
            'reason' => $validation['reason'],
            'violations' => $violationList,
            'violationDetails' => $violationSummary
        ];

        return $response;
    }

    public function parseGraphQLOperation(?array $body): ?array
    {
        try {
            if (!$body || !isset($body['query'])) {
                return null;
            }

            $operationName = $body['operationName'] ?? $this->extractOperationNameFromQuery($body['query']);
            return $operationName ? ['name' => $operationName] : null;
        } catch (\Exception $e) {
            return null;
        }
    }

    private function extractOperationNameFromQuery(string $query): ?string
    {
        try {
            if (preg_match('/(query|mutation|subscription)\s+(\w+)/i', $query, $matches)) {
                return $matches[2] ?? null;
            }
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    public function getConfigSummary(): array
    {
        $config = $this->getCurrentConfig();
        $enabledProtections = array_keys(array_filter($config['protections'], fn($p) => $p['enabled']));

        return [
            'enabled' => $config['enabled'],
            'responseType' => $config['responseType'],
            'enabledProtections' => $enabledProtections,
            'disabledProtections' => array_diff(array_keys($config['protections']), $enabledProtections),
            'cacheEnabled' => $config['enableCache'],
            'validatedMethods' => $config['validatedMethods'],
            'ignoredPaths' => $config['ignoredPaths'],
            'configSource' => $this->configCache ? 'api' : 'fallback',
            'configAge' => isset($config['configFetchedAt']) ?
                round((time() * 1000 - strtotime($config['configFetchedAt']) * 1000) / 1000) : null,
            'lastConfigUpdate' => $config['configUpdatedAt'] ?? null,
            'refreshInterval' => $this->configRefreshInterval / 1000 . 's'
        ];
    }

    public function middleware(): callable
    {
        if ($this->getCurrentConfig()['logRequests']) {
            error_log('🛡️  [WAF Client] Initialized with config: ' . json_encode($this->getConfigSummary()));
        }

        return function($req, $res, $next) {
            try {
                // Check if config needs refresh
                if ((time() * 1000 - $this->lastConfigFetch) > $this->configRefreshInterval) {
                    $this->fetchConfiguration();
                }

                $this->cleanupCache();
                $config = $this->getCurrentConfig();

                if (!$config['enabled']) {
                    return $next();
                }

                $path = $req['path'] ?? $req['url'];
                if ($this->shouldIgnorePath($path)) {
                    if ($config['logRequests']) {
                        error_log("⏭️  [WAF Client] Ignoring path: {$path}");
                    }
                    return $next();
                }

                if (!$this->shouldValidateMethod($req['method'])) {
                    if ($config['logRequests']) {
                        error_log("⏭️  [WAF Client] Ignoring method: {$req['method']}");
                    }
                    return $next();
                }

                $requestHash = $this->createRequestHash($req);
                $cachedResult = $this->checkCache($requestHash);

                if ($cachedResult) {
                    if ($config['logRequests']) {
                        error_log('📋 [WAF Client] Using cached result');
                    }

                    if (!$cachedResult['allowed'] || $cachedResult['blocked']) {
                        return $this->createBlockedResponse($req, $res, $cachedResult, true);
                    }

                    return $next();
                }

                $validation = $this->validateRequest($req);
                $this->saveToCache($requestHash, $validation);

                if (!$validation['allowed'] || $validation['blocked']) {
                    if ($config['logRequests']) {
                        $this->logBlockedRequest($validation);
                    }

                    return $this->createBlockedResponse($req, $res, $validation);
                }

                if ($config['logRequests']) {
                    error_log('✅ [WAF Client] Request approved');
                }

                return $next();

            } catch (\Exception $error) {
                error_log('❌ [WAF Client] Internal error: ' . $error->getMessage());

                $config = $this->getCurrentConfig();
                if ($config['onWafError'] === 'block' || $config['blockOnError']) {
                    $errorValidation = [
                        'reason' => 'WAF_CLIENT_ERROR',
                        'message' => 'Security validation failed due to internal error'
                    ];

                    return $this->createBlockedResponse($req, $res, $errorValidation);
                }

                return $next();
            }
        };
    }

    private function logBlockedRequest(array $validation): void
    {
        $violationDetails = $validation['validationResults']['violations'] ?? [];
        $violationSummary = implode(', ', array_map(function($v) {
            $type = str_replace(['_DETECTED', '_'], ['', ' '], $v['type']);
            $count = is_array($v['details']) ? count($v['details']) : 1;
            return "{$type} ({$count})";
        }, $violationDetails));

        error_log('🚫 [WAF Client] Request blocked: ' . json_encode([
            'reason' => $validation['reason'],
            'violations' => $validation['validationResults']['totalViolations'] ?? 0,
            'types' => $violationSummary ?: 'Unknown',
            'severity' => count(array_filter($violationDetails, fn($v) =>
                in_array($v['severity'], ['CRITICAL', 'HIGH'])
            )) . ' high/critical'
        ]));

        if (!empty($violationDetails)) {
            error_log('🔍 [WAF Client] Violation details:');
            foreach ($violationDetails as $index => $violation) {
                $details = is_array($violation['details']) ? count($violation['details']) . ' instances' : $violation['details'];
                error_log("  " . ($index + 1) . ". {$violation['type']} ({$violation['severity']}): {$details}");
            }
        }
    }

    private function createBlockedResponse(array $req, $res, array $validation, bool $cached = false)
    {
        $config = $this->getCurrentConfig();
        if ($config['responseType'] === 'graphql') {
            $operationInfo = $this->parseGraphQLOperation($req['body']);
            $graphqlResponse = $this->createGraphQLErrorResponse($operationInfo, $validation);

            http_response_code(200);
            header('Content-Type: application/json');
            echo json_encode($graphqlResponse);
            return;
        } else {
            $violationDetails = $validation['validationResults']['violations'] ?? [];
            $violationSummary = implode(', ', array_map(function($v) {
                return str_replace(['_DETECTED', '_'], ['', ' '], $v['type']);
            }, $violationDetails));

            $enhancedMessage = $violationSummary ?
                ($validation['message'] ?? 'Request blocked') . " ({$violationSummary})" :
                ($validation['message'] ?? 'Request blocked');

            $response = [
                'success' => false,
                'blocked' => true,
                'reason' => $validation['reason'],
                'message' => $enhancedMessage,
                'violations' => $violationSummary,
                'details' => $validation['validationResults'] ?? null
            ];

            if ($cached) {
                $response['cached'] = true;
            }

            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode($response);
            return;
        }
    }

    public function destroy(): void
    {
        $this->cache = [];
        $this->rateLimitMap = [];

        if ($this->getCurrentConfig()['logRequests']) {
            error_log('🛑 [WAF Client] Client destroyed and cleaned up');
        }
    }
}