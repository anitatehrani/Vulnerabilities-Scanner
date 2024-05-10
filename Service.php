<?php

require_once 'vendor/autoload.php';

class MockVulnerabilityScanner implements VulnerabilityScanner {
    public function scan($serviceType, $serviceVersion) {
        $vulnerabilities = [];
        if ($serviceType === 'Apache' && $serviceVersion === '2.4.48') {
            $vulnerabilities[] = ['id' => 'CVE-2023-XXXX', 'description' => 'Sample Apache vulnerability', 'severity' => 'High'];
        } elseif ($serviceType === 'Wordpress' && $serviceVersion === '6.1.1') {
            $vulnerabilities[] = ['id' => 'CVE-2024-YYYY', 'description' => 'Sample Wordpress vulnerability', 'severity' => 'Medium'];
        }
        return $vulnerabilities;
    }
}

interface VulnerabilityScanner {
    public function scan($serviceType, $serviceVersion);
}

class Service {
    public $type;
    public $url;
    public $version;
    public $vulnerabilities = [];

    public function __construct($type, $url) {
        $this->type = $type;
        $this->url = $url;
    }

    public function identifyVersion() {
        $methodName = 'identify' . ucfirst($this->type) . 'Version';
        if (method_exists($this, $methodName)) {
            $this->$methodName();
        } else {
            throw new Exception("Version identification not implemented for service type: {$this->type}");
        }
    }

    private function identifyApacheVersion() {
        $ch = curl_init($this->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        $response = curl_exec($ch);
        curl_close($ch);

        if (preg_match('/Apache\/(\d+\.\d+(\.\d+)?)/', $response, $matches)) {
            $this->version = $matches[1];
        } else {
            throw new Exception("Unable to identify Apache version");
        }
    }

    private function identifyWordpressVersion() {
        $html = file_get_contents($this->url);

        // Check if HTML content was retrieved successfully
        if ($html !== false) {
            // Search for the WordPress version pattern in the HTML content
            if (preg_match('/<meta name="generator" content="WordPress (\d+\.\d+\.\d+)/', $html, $matches)) {
                // Extract the version number from the match
                $this->version = $matches[1];
            } else {
                return null; // WordPress version not found
            }
        } else {
            return null; // Failed to retrieve HTML content from URL
        }
    }

private function identifyMysqlVersion() {

    $html = file_get_contents($this->url);

    // Check if HTML content was retrieved successfully
    if ($html !== false) {
        // Search for the MySQL version pattern in the HTML content
        if (preg_match('/MySQL (\d+\.\d+(\.\d+)?)/', $html, $matches)) {
                // Extract the version number from the match
            $this->version = $matches[1];
        } else {
            return null; // MySQL version not found
        }
    } else {
        return null; // Failed to retrieve HTML content from URL
    }
}

    public function checkVulnerabilities() {
        $token = 'DZ4S5QHK6XWWP5XOHU8HGBYAX2HQEPZT49EFMHOASDHU89VRJ7N2M40INXG4D64S';
        $url = 'https://vulners.com/api/v3/search/lucene/?query=' . urlencode($this->type . ' ' . $this->version);

        $options = [
            'http' => [
                'header' => "Authorization: Token " . $token
            ]
        ];
        $context = stream_context_create($options);

        $response = file_get_contents($url, false, $context);

        if ($response === false) {
            throw new Exception("Unable to get vulnerabilities from Vulners API");
        }

        $responseArray = json_decode($response, true);
        if (isset($responseArray['data']['search'])) {
            $vulnerabilities = $responseArray['data']['search'];
            file_put_contents('vulnerabilities' . $this->type . '.txt', json_encode($vulnerabilities));
        }
    }
}

try {

    $json = file_get_contents('inputs.json');
    $services = json_decode($json, true);

    foreach ($services as &$service) {
        $serviceObject = new Service($service['type'], $service['url']);
        try {
            $serviceObject->identifyVersion();
            $serviceObject->checkVulnerabilities();
//            print_r($serviceObject);
            $service['version'] = $serviceObject->version;
            $service['vulnerabilities'] = $serviceObject->vulnerabilities;
        } catch (Exception $e) {
            echo "Error processing service ({$service['type']}): " . $e->getMessage() . PHP_EOL;
        }
    }
    $report = generateReport($services);
    echo $report;

} catch (Exception $e) {
    echo "An unexpected error occurred: " . $e->getMessage() . PHP_EOL;
}

function generateReport($services) {
    $report = "Vulnerability Report\n";
    foreach ($services as $service) {
        $report .= "Service: {$service['type']}\n";
        $report .= "URL: {$service['url']}\n";
        $report .= "Version: {$service['version']}\n";
        $report .= "\n";
    }
    return $report;
}