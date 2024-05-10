# Vulnerabilities Scanner

This project is a PHP-based vulnerability scanner that leverages the National Vulnerability Database's (NVD) Common Vulnerabilities and Exposures (CVE) API. The scanner fetches vulnerability data for specific services and versions, providing a comprehensive overview of potential security risks associated with the services in use.
## Getting Started

The following instructions will guide you through obtaining a copy of this project and running it on your local machine for development and testing purposes.
### Prerequisites
Before you begin, ensure that you have the following software installed on your machine:  
- **PHP**: The project is written in PHP. You can download PHP from the [official PHP website](https://www.php.net/downloads.php).
- **Composer**: This project uses Composer for dependency management. You can download Composer from the [official Composer website](https://getcomposer.org/download/).

### Installing
To set up the project on your local machine, follow these steps:
1. Clone the repository: `git clone https://github.com/anitatehrani/Vulnerabilities_Scanner.git`
2. Navigate to the project directory: `cd Vulnerabilities_Scanner`
3. Install dependencies: `composer install`

## Usage

To use the vulnerability scanner, you need to create an instance of the `Service` class and call the `checkVulnerabilities` method.

```php
$service = new Service($url, $type, $version);
$service->checkVulnerabilities();
```

This will fetch the vulnerability data from the NVD's CVE API and save it to a file.

## Running the tests
To run the tests, use the following command in the project root directory:
`phpunit --bootstrap vendor/autoload.php tests`

Setting up the services
The vulnerability scanner can check for vulnerabilities in Apache, WordPress, and MySQL services. Here's how you can set up these services for testing:  

#### Apache
1. Install Apache using your package manager. For example, on Ubuntu, you can use `sudo apt install apache2`.
2. Check the Apache version by running `apache2 -v`.

#### WordPress:
1. Download the latest version of WordPress from the [official website](https://wordpress.org/download/).
2. Extract the downloaded file to the Apache document root (usually /var/www/html).
3. Follow the instructions in the wp-admin/install.php script to set up WordPress.

#### XAMPP
1. Download XAMPP from the [official website](https://www.apachefriends.org/index.html).
2. Follow the instructions on the website to install XAMPP.
3. Once installed, you can use the XAMPP control panel to start Apache, MySQL, and other services.
4. You can check the versions of Apache and MySQL from the XAMPP control panel.


## Understanding the Code

The main functionality of the vulnerability scanner is contained in the `Service.php` file. This file defines a `Service` class that represents a service to be scanned for vulnerabilities.

The `Service` class has several methods:

- `identifyVersion()`: This method identifies the version of the service. It calls a specific method based on the type of the service (e.g., `identifyApacheVersion()`, `identifyWordpressVersion()`, `identifyMysqlVersion()`).

- `checkVulnerabilities()`: This method checks the service for vulnerabilities. It constructs a CPE (Common Platform Enumeration) name and sends a request to the NVD's CVE API. The response from the API is then processed and saved to a file.

- `extractVulnerabilities()`: This method is called by `checkVulnerabilities()`. It processes the response from the CVE API and extracts the relevant vulnerability data.

The `Service.php` file also includes a `try`/`catch` block that creates `Service` objects, identifies the version of the service, checks for vulnerabilities, and generates a report. This block of code is the entry point of the application.

The `Service.php` file ends with a `generateReport()` function that generates a report of the services and their vulnerabilities. This function is called in the `try`/`catch` block.

### The inputs.json file

The `inputs.json` file is used to provide input to the vulnerability scanner. It contains an array of objects, each representing a service to be scanned. Each object has two properties: `type` and `url`.

- `type`: This is the type of the service (e.g., 'apache', 'wordpress', 'mysql'). The `Service` class uses this value to determine which method to call to identify the version of the service and to construct the CPE name for the CVE API request.

- `url`: This is the URL of the service. The `Service` class uses this value to send a request to the service and identify its version.

Here's an example of what the `inputs.json` file might look like:

```json
[
  {
    "type": "Apache",
    "url": "http://localhost"
  },
  {
    "type": "Wordpress",
    "url": "http://localhost/wordpress"
  },
  {
    "type": "MySQL",
    "url": "http://localhost/phpmyadmin"
  }
]