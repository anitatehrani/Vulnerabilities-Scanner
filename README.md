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
```

This will fetch the vulnerability data from the NVD's CVE API and save it to a file.

## Running the tests
To run the tests, use the following command in the project root directory:
`phpunit --bootstrap vendor/autoload.php tests`

Setting up the services
The vulnerability scanner can check for vulnerabilities in Apache, WordPress, and MySQL services. Here's how you can set up these services for testing:  

- Apache:
Install Apache using your package manager. 
For example, on Ubuntu, you can use `sudo apt install apache2`.
Check the Apache version by running `apache2 -v`.

- WordPress:
Download the latest version of WordPress from the official website.
Extract the downloaded file to the Apache document root (usually /var/www/html).
Follow the instructions in the wp-admin/install.php script to set up WordPress.

- MySQL:
Install MySQL using your package manager. 
For example, on Ubuntu, you can use `sudo apt install mysql-server`.
Check the MySQL version by running `mysql -V`.


## Live Demonstration
For the live demonstration, you will need to have Apache, WordPress, and MySQL installed and running on your machine. Follow the instructions in the "Setting up the services" section to set up these services.  Once the services are set up, you can use the vulnerability scanner to check for vulnerabilities. Here's how:  
1. Open a terminal and navigate to the project directory.
2. Run the script with the command **php Service.php**.
3. The script will fetch the vulnerability data from the NVD's CVE API and save it to a file named **vulnerabilities_<service_type>.txt**.

## Understanding the Code
The main functionality of the vulnerability scanner is contained in the **Service.php** file. This file defines a **Service** class that represents a service to be scanned for vulnerabilities. 
The **Service** class has several methods:  
- **identifyVersion():** This method identifies the version of the service. It calls a specific method based on the type of the service (e.g., **identifyApacheVersion(), identifyWordpressVersion(), identifyMysqlVersion()**).  
- **checkVulnerabilities():** This method checks the service for vulnerabilities. It constructs a CPE (Common Platform Enumeration) name and sends a request to the NVD's CVE API. The response from the API is then processed and saved to a file.  
- **extractVulnerabilities():** This method is called by **checkVulnerabilities()**. It processes the response from the CVE API and extracts the relevant vulnerability data. 

The **Service.php** file also includes a **try/catch** block that creates Service objects, identifies the version of the service, checks for vulnerabilities, and generates a report. This block of code is the entry point of the application.  
The **Service.php** file ends with a **generateReport()** function that generates a report of the services and their vulnerabilities. This function is called in the **try/catch** block.