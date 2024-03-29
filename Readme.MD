# MITM Attacker

This project is a tool that combines different attack techniques in the field of network security. It includes methods such as ARP poisoning, DNS spoofing, and HTTP traffic monitoring. It is important to comply with laws and ethical rules when using the project.

## Contents

1. [Installation](#installation)
2. [Project Content](#project-content)
    - [ARP Spoof](#arp-spoof)
    - [DNS Spoof](#dns-spoof)
    - [Packet Sniffing](#packet-sniffing)
    - [Fake Websites](#fake-websites)
3. [Running](#running)
4. [Notes](#notes)
5. [Disclaimer](#disclaimer)
6. [License](#license)


## Installation



1. Download the project files to your computer.
2. To install the required Python libraries, enter the following command in a terminal or command prompt:

  
```bash
    pip install -r requirements.txt
```

## Project Content

This project combines the following attack methods:

### ARP Spoof

The project allows the attacker to take control of network traffic by poisoning the ARP tables in the target network.

### DNS Spoof

DNS spoofing is used to redirect the victim to a specific website.

### Packet Sniffing

The `packet_listener.py` file in the project monitors the traffic of HTTP sites visited by the victim and captures sensitive information such as username/password. It also records DNS packets that the victim interacts with, whether knowingly or unknowingly, to the `data_sniffed.txt` file.

### Fake Websites

The `instagram`, `twitter` and `websiteos` directories in the project contain fake websites.

- `instagram` and `twitter`: These websites redirect the victim to fake login pages for Instagram and Twitter, allowing the attacker to steal the victim's username and password.
- `websiteos`: This is a test site with a keylogger. The keys pressed by the victim while on the site are recorded to the `keylog.txt` file in the `/var/www/html` directory.

## Running

1. Start Apache2. `sudo service apache2 start`
2. Run the project as follows.


```bash
python main.py -t <target_ip> -r <router_ip> -l <local_ip>
```

### Notes

- Apache2 must be started before using the project.
- The project should be run as root and it should be noted that the html file in the Apache file will be deleted when it is run.
- It should be remembered that browsers keep DNS cache, so it may be difficult to spoof frequently visited sites.
- Using the project for malicious purposes is prohibited and no liability is accepted.
- If your interface is not wlan0, do not forget to change -> "packet_listener.py, line 36"


### Disclaimer

This project, "MITM Attacker," is intended for educational and testing purposes only. The project demonstrates various network security attack techniques, including ARP poisoning, DNS spoofing, and packet sniffing.

**Usage Warning:** This tool should be used responsibly and solely on systems and networks for which you have explicit authorization. Unauthorized use of this tool for malicious or illegal activities is strictly prohibited. The project's author and contributors do not endorse, encourage, or support any form of unauthorized access, data interception, or other illicit activities.

By using this project, you acknowledge that you have read and understood this disclaimer. The project is provided "as is," and the authors make no representations or warranties regarding the accuracy, completeness, or suitability of the project for any purpose.

The authors shall not be liable for any direct, indirect, consequential, or incidental damages arising out of the use or inability to use the project. Users are solely responsible for their actions and should comply with all applicable laws and ethical guidelines.

**Legal Notice:** Using this project for unauthorized purposes may lead to legal consequences. It is your responsibility to ensure compliance with all relevant laws and regulations.

**Warning:** Any misuse of this project may result in legal consequences. Use it at your own risk and always respect the privacy and security of others.


### License

- This project is licensed under the MIT License. For more information, see the  [LICENSE](LICENSE) file.

- This project should not be used for illegal activities. No liability is accepted.

