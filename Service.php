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

        if ($html !== false) {
            if (preg_match('/<meta name="generator" content="WordPress (\d+\.\d+\.\d+)/', $html, $matches)) {
                $this->version = $matches[1];
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

private function identifyMysqlVersion() {

    $html = file_get_contents($this->url);

     if ($html !== false) {
         if (preg_match('/MySQL (\d+\.\d+(\.\d+)?)/', $html, $matches)) {
            $this->version = $matches[1];
        } else {
            return null;
        }
    } else {
        return null;
    }
}

    public function checkVulnerabilities() {
        $cpeName = "cpe:2.3:a:$this->type:$this->type:$this->version:*:*:*:*:*:*:*";
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" . urlencode($cpeName);

        $response = file_get_contents($url);

        $formatted = $this->extractVulnerabilities($response);

        $jsonOutput = json_encode($formatted, JSON_PRETTY_PRINT);

        file_put_contents('vulnerabilities_' . $this->type . '.txt', $jsonOutput);
    }


    function extractVulnerabilities($jsonText) {
        $data = json_decode($jsonText, true);

        $vulnerabilities = $data['vulnerabilities'];

        $formattedVulnerabilities = [];

        foreach ($vulnerabilities as $vulnerability) {
            $formattedVulnerability = [
                'CVE-ID' => $vulnerability['cve']['id'],
                'Published' => $vulnerability['cve']['published'],
                'Last Modified' => $vulnerability['cve']['lastModified'],
                'Description' => $vulnerability['cve']['descriptions'][0]['value'],
                'Base Severity' => $vulnerability['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
            ];
            $formattedVulnerabilities[] = $formattedVulnerability;
        }

        return $formattedVulnerabilities;
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
    $report = "Report\n";
    foreach ($services as $service) {
        $report .= "Service: {$service['type']}\n";
        $report .= "URL: {$service['url']}\n";
        $report .= "Version: {$service['version']}\n";
        $report .= "\n";
    }
    return $report;
}