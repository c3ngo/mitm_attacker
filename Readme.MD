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
5. [License](#license)


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
python main.py -t <hedef_ip> -r <router_ip> -l <local_ip>
```

### Notes

- Apache2 must be started before using the project.
- It should be remembered that browsers keep DNS cache, so it may be difficult to spoof frequently visited sites.
- Instagram ve Twitter yanında Websiteos seçilmesinin sebebi, sitenin http kullanması ve tarayıcıların DNS cache'inde tutulmaması.
- Using the project for malicious purposes is prohibited and no liability is accepted.
- If your interface is not wlan0, do not forget to change -> "packet_listener.py, line 36"
- When you interrupted the project with "ctrl + c", do it twice. When you interrupted project, run "iptables --flush". Project does not stop exactly. Project need more configuration.



### License

- This project is licensed under the MIT License. For more information, see the  [LICENSE](LICENSE) file.

- This project should not be used for illegal activities. No liability is accepted.

