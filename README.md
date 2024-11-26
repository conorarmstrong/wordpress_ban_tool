# IP Access Logger for WordPress

**IP Access Logger** is a lightweight WordPress plugin that logs and tracks IP addresses accessing your website. It allows you to monitor specific user interactions, maintain logs, and optionally analyze the data for security or administrative purposes.

---

## Features

- **Log IP Addresses**: Automatically logs the IP addresses of users visiting your site.
- **Date and Time Tracking**: Records the timestamp of each visit for audit purposes.
- **Whois Integration**: Links logged IP addresses to their respective Whois lookup pages for quick identification.
- **Database Storage**: Saves logs in the database for later review and analysis.
- **Admin Panel Integration**: View and manage logged IPs directly from the WordPress dashboard.

---

## Installation

1. **Download the Plugin**:
   Download the `ip-access-logger.zip` file.

2. **Upload to WordPress**:
   - Navigate to your WordPress dashboard.
   - Go to `Plugins` > `Add New` > `Upload Plugin`.
   - Select the downloaded `ip-access-logger.php` file and click **Install Now**.

3. **Activate the Plugin**:
   After installation, go to `Plugins` > `Installed Plugins` and activate **IP Access Logger**.

4. **Configuration**:
   - No additional setup is required. The plugin works out of the box.
   - Visit the **Tools** or **Settings** section in your WordPress dashboard to access logs (if integrated).

---

## Usage

1. **Log IP Addresses**:
   The plugin automatically logs IP addresses visiting your site and stores them in the database.

2. **View Logs**:
   - Access the plugin's admin page to view logged IPs.
   - Each logged IP address is linked to its Whois lookup page (e.g., `https://who.is/whois-ip/ip-address/{IP}`).

3. **Analyze Data**:
   Use the logged IPs for security purposes, traffic analysis, or debugging.

---

## Development

### File Structure

- **`ip-access-logger.php`**:
  - The main plugin file contains the core logic for logging IPs and integrating with WordPress.

### Hooks and Actions

The plugin integrates into WordPress using:
- **Hooks**: To capture events like user logins or page visits.
- **Database Storage**: Uses WordPress's `$wpdb` class for secure and efficient database interaction.

---

## Security and Best Practices

- The plugin escapes and sanitizes all input/output to prevent XSS or SQL injection vulnerabilities.
- Ensure your database is regularly backed up before installing new plugins.

---

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository on GitHub.
2. Create a feature branch.
3. Submit a pull request with a detailed explanation of the changes.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Support

If you encounter issues or have questions, feel free to open an issue on this repository or contact us via the support page.

---

## Acknowledgments

- Developed with ❤️ by Conor Armstrong.
- Built using the WordPress plugin development framework.
