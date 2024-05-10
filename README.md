# Vulnerabilities Scanner

This project is a vulnerability scanner for services. It uses the NVD's CVE API to fetch vulnerability data for specific services and versions.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- PHP
- Composer

### Installing

1. Clone the repository: `git clone https://github.com/anitatehrani/Vulnerabilities_Scanner.git`
2. Navigate to the project directory: `cd Vulnerabilities_Scanner`
3. Install dependencies: `composer install`

## Usage

To use the vulnerability scanner, you need to create an instance of the `Service` class and call the `checkVulnerabilities` method.

```php
$service = new Service($url, $type, $version);
$service->checkVulnerabilities();
