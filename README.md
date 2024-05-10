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
phpunit --bootstrap vendor/autoload.php tests

Setting up the services
The vulnerability scanner can check for vulnerabilities in Apache, WordPress, and MySQL services. Here's how you can set up these services for testing:  
Apache
Install Apache using your package manager. For example, on Ubuntu, you can use sudo apt install apache2.
Check the Apache version by running apache2 -v.

WordPress
Download the latest version of WordPress from the official website.
Extract the downloaded file to the Apache document root (usually /var/www/html).
Follow the instructions in the wp-admin/install.php script to set up WordPress.

MySQL
Install MySQL using your package manager. For example, on Ubuntu, you can use sudo apt install mysql-server.
Check the MySQL version by running mysql -V.
Contributing
Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests to us.  



