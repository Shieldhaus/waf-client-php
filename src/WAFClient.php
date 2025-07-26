<?php

namespace NetFend\WAF;
/**
 * WAF Client SDK - Enhanced Version with Custom Protection Settings (PHP)
 * Converted from Node.js version - handles 403 responses from WAF server
 */

class WAFClient
{
    private array $config;
    private array $cache = [];
    private array $rateLimitMap = [];

    public function __construct(array $options = [])
    {
        if (empty($options['apiKey'])) {
            throw new \InvalidArgumentException('WAF API Key is required');
        }

        $this->config = [
            'apiKey' => $options['apiKey'],
            'wafEndpoint' => $options['wafEndpoint'] ?? 'https://graphnet.emailsbit.com/waf/v1/validate',
            'timeout' => $options['timeout'] ?? 5000,
            'enabled' => $options['enabled'] ?? true,
            'blockOnError' => $options['blockOnError'] ?? true,
            'logRequests' => $options['logRequests'] ?? false,
            
            // Response type - 'rest' or 'graphql'
            'responseType' => $options['responseType'] ?? 'rest',
            
            // Custom protection settings (sent to server)
            'protections' => [
                'xss' => ['enabled' => $options['protections']['xss']['enabled'] ?? true],
                'sqlInjection' => ['enabled' => $options['protections']['sqlInjection']['enabled'] ?? true],
                'rce' => ['enabled' => $options['protections']['rce']['enabled'] ?? true],
                'pathTraversal' => ['enabled' => $options['protections']['pathTraversal']['enabled'] ?? true],
                'maliciousHeaders' => ['enabled' => $options['protections']['maliciousHeaders']['enabled'] ?? true],
                'fileUpload' => ['enabled' => $options['protections']['fileUpload']['enabled'] ?? true],
                'ipCheck' => ['enabled' => $options['protections']['ipCheck']['enabled'] ?? true],
            ],
            
            'onWafError' => $options['onWafError'] ?? 'allow', // 'allow' or 'block'
            'ignoredPaths' => $options['ignoredPaths'] ?? ['/health'],
            'validatedMethods' => $options['validatedMethods'] ?? ['POST', 'PUT', 'PATCH', 'DELETE'],
            'customHeaders' => $options['customHeaders'] ?? [],
            
            // Cache settings
            'enableCache' => $options['enableCache'] ?? true,
            'cacheTimeout' => $options['cacheTimeout'] ?? 60000,
            
            // Rate limiting (client-side)
            'rateLimitRequests' => $options['rateLimitRequests'] ?? 100,
            'rateLimitWindow' => $options['rateLimitWindow'] ?? 60000, // 1 minute
        ];

        $this->validateProtectionSettings();
        $this->startCacheCleaner();
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
        foreach ($this->config['ignoredPaths'] as $ignoredPath) {
            if (stripos($path, $ignoredPath) !== false) {
                return true;
            }
        }
        return false;
    }

    private function shouldValidateMethod(string $method): bool
    {
        return in_array(strtoupper($method), $this->config['validatedMethods']);
    }

    private function checkRateLimit(string $clientIp): bool
    {
        if (!$this->config['rateLimitRequests']) {
            return true;
        }
        
        $now = time() * 1000; // milliseconds
        $windowStart = $now - $this->config['rateLimitWindow'];
        
        if (!isset($this->rateLimitMap[$clientIp])) {
            $this->rateLimitMap[$clientIp] = [];
        }
        
        $requests = $this->rateLimitMap[$clientIp];
        
        // Remove old requests
        $validRequests = array_filter($requests, fn($timestamp) => $timestamp > $windowStart);
        $this->rateLimitMap[$clientIp] = array_values($validRequests);
        
        if (count($validRequests) >= $this->config['rateLimitRequests']) {
            return false;
        }
        
        $this->rateLimitMap[$clientIp][] = $now;
        return true;
    }

    private function createRequestHash(array $req): ?string
    {
        if (!$this->config['enableCache']) {
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
            'protections' => $this->config['protections']
        ];
        
        return md5(json_encode($data));
    }

    private function checkCache(?string $hash): ?array
    {
        if (!$hash || !$this->config['enableCache'] || !isset($this->cache[$hash])) {
            return null;
        }
        
        $cached = $this->cache[$hash];
        if ((time() * 1000) - $cached['timestamp'] > $this->config['cacheTimeout']) {
            unset($this->cache[$hash]);
            return null;
        }
        
        return $cached['result'];
    }

    private function saveToCache(?string $hash, array $result): void
    {
        if (!$hash || !$this->config['enableCache']) {
            return;
        }
        
        $this->cache[$hash] = [
            'result' => $result,
            'timestamp' => time() * 1000
        ];
    }

    public function startCacheCleaner(): void
    {
        // Em PHP, isso seria melhor implementado com um cron job ou task scheduler
        // Por enquanto, limpamos a cada validação para evitar memory leaks
    }

    private function cleanupCache(): void
    {
        $now = time() * 1000;
        
        // Clean cache
        foreach ($this->cache as $hash => $data) {
            if ($now - $data['timestamp'] > $this->config['cacheTimeout']) {
                unset($this->cache[$hash]);
            }
        }
        
        // Clean rate limit map
        $rateLimitWindow = $this->config['rateLimitWindow'];
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
        try {
            $clientIp = $req['ip'] ?? $req['connection']['remoteAddress'] ?? 'unknown';
            
            // Check rate limit
            if (!$this->checkRateLimit($clientIp)) {
                return [
                    'allowed' => false,
                    'blocked' => true,
                    'reason' => 'RATE_LIMIT_EXCEEDED',
                    'message' => sprintf(
                        'Rate limit exceeded: %d requests per %d seconds',
                        $this->config['rateLimitRequests'],
                        $this->config['rateLimitWindow'] / 1000
                    )
                ];
            }

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
                
                // Send custom protection settings to server
                'protections' => $this->config['protections'],
                
                'clientInfo' => [
                    'apiKey' => $this->config['apiKey'],
                    'version' => '2.0.0',
                    'responseType' => $this->config['responseType']
                ]
            ];

            if ($this->config['logRequests']) {
                $enabledProtections = array_keys(array_filter(
                    $this->config['protections'], 
                    fn($p) => $p['enabled']
                ));
                
                error_log('🔍 [WAF Client] Sending for validation: ' . json_encode([
                    'method' => $payload['method'],
                    'path' => $payload['path'],
                    'hasBody' => !empty($payload['body']),
                    'protections' => $enabledProtections,
                    'ip' => $clientIp
                ]));
            }

            // Make HTTP request
            $headers = array_merge([
                'Content-Type: application/json',
                'Authorization: ' . $this->config['apiKey'],
                'X-WAF-Client: php',
                'X-WAF-Response-Type: ' . $this->config['responseType'],
            ], array_map(fn($k, $v) => "$k: $v", array_keys($this->config['customHeaders']), $this->config['customHeaders']));

            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => implode("\r\n", $headers),
                    'content' => json_encode($payload),
                    'timeout' => $this->config['timeout'] / 1000,
                    'ignore_errors' => true // Don't throw on 4xx/5xx
                ]
            ]);

            $response = file_get_contents($this->config['wafEndpoint'], false, $context);
            
            if ($response === false) {
                throw new \Exception('Network error - unable to connect');
            }

            $responseData = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid JSON response');
            }

            if ($this->config['logRequests']) {
                $appliedProtections = [];
                if (isset($responseData['appliedProtections'])) {
                    $appliedProtections = array_keys(array_filter(
                        $responseData['appliedProtections'], 
                        fn($p) => $p['enabled'] ?? false
                    ));
                }

                error_log('📨 [WAF Client] Server response: ' . json_encode([
                    'blocked' => $responseData['blocked'] ?? false,
                    'reason' => $responseData['reason'] ?? null,
                    'violations' => $responseData['validationResults']['totalViolations'] ?? 0,
                    'appliedProtections' => $appliedProtections
                ]));
            }

            return $responseData;

        } catch (\Exception $error) {
            // Handle network/timeout errors
            if ($this->config['logRequests']) {
                error_log('❌ [WAF Client] Network/timeout error: ' . json_encode([
                    'message' => $error->getMessage(),
                    'isNetworkError' => true
                ]));
            }

            if ($this->config['onWafError'] === 'block' || $this->config['blockOnError']) {
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

        // Include detailed violation information in GraphQL response
        $violationDetails = $validation['validationResults']['violations'] ?? [];
        $violationSummary = array_map(function($v) {
            return [
                'type' => $v['type'],
                'severity' => $v['severity'],
                'count' => is_array($v['details']) ? count($v['details']) : 1,
                'readableType' => str_replace(['_DETECTED', '_'], ['', ' '], $v['type'])
            ];
        }, $violationDetails);

        // Create human-readable violation list
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
        $enabledProtections = array_keys(array_filter(
            $this->config['protections'], 
            fn($p) => $p['enabled']
        ));

        return [
            'enabled' => $this->config['enabled'],
            'responseType' => $this->config['responseType'],
            'enabledProtections' => $enabledProtections,
            'disabledProtections' => array_diff(array_keys($this->config['protections']), $enabledProtections),
            'cacheEnabled' => $this->config['enableCache'],
            'rateLimitEnabled' => !empty($this->config['rateLimitRequests']),
            'validatedMethods' => $this->config['validatedMethods'],
            'ignoredPaths' => $this->config['ignoredPaths']
        ];
    }

    public function middleware(): callable
    {
        if ($this->config['logRequests']) {
            error_log('🛡️  [WAF Client] Initialized with config: ' . json_encode($this->getConfigSummary()));
        }

        return function($req, $res, $next) {
            try {
                // Cleanup cache periodically
                $this->cleanupCache();

                if (!$this->config['enabled']) {
                    return $next();
                }

                $path = $req['path'] ?? $req['url'];
                if ($this->shouldIgnorePath($path)) {
                    if ($this->config['logRequests']) {
                        error_log("⏭️  [WAF Client] Ignoring path: {$path}");
                    }
                    return $next();
                }

                if (!$this->shouldValidateMethod($req['method'])) {
                    if ($this->config['logRequests']) {
                        error_log("⏭️  [WAF Client] Ignoring method: {$req['method']}");
                    }
                    return $next();
                }

                $requestHash = $this->createRequestHash($req);
                $cachedResult = $this->checkCache($requestHash);
                
                if ($cachedResult) {
                    if ($this->config['logRequests']) {
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
                    if ($this->config['logRequests']) {
                        $this->logBlockedRequest($validation);
                    }
                    
                    return $this->createBlockedResponse($req, $res, $validation);
                }

                if ($this->config['logRequests']) {
                    error_log('✅ [WAF Client] Request approved');
                }

                return $next();

            } catch (\Exception $error) {
                error_log('❌ [WAF Client] Internal error: ' . $error->getMessage());
                
                if ($this->config['onWafError'] === 'block' || $this->config['blockOnError']) {
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

        // Log individual violation details for debugging
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
        if ($this->config['responseType'] === 'graphql') {
            $operationInfo = $this->parseGraphQLOperation($req['body']);
            $graphqlResponse = $this->createGraphQLErrorResponse($operationInfo, $validation);
            
            // Set status and return JSON response
            http_response_code(200);
            header('Content-Type: application/json');
            echo json_encode($graphqlResponse);
            return;
        } else {
            // Enhanced REST response with human-readable violation summary
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
}