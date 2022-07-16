<div id="top"></div>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/omeround3/veach">
    <img src="https://user-images.githubusercontent.com/45568925/175764349-30c0ffc9-99bb-4e78-832a-83288ef4db90.png" alt="Logo" width="250" height="250">
  </a>

<h3 align="center">VEACH Project</h3>

  <p align="center">
    VEACH – Vulnerabilities Exposure and Analysis in Code and Hardware
    <br />
    Software & hardware vulnerabilities detection and elimination system for Debian GNU/Linux operating system
    <br />
    <a href="https://github.com/omeround3/veach"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/omeround3/veach">View Demo</a>
    ·
    <a href="https://github.com/omeround3/veach/issues">Report Bug</a>
    ·
    <a href="https://github.com/omeround3/veach/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

<!-- [![Product Name Screen Shot][product-screenshot]](https://example.com) -->
**VEACH** – Vulnerabilities Exposure and Analysis in Code and Hardware.

VEACH project is designed to help novice Linux-Debian users to keep their system secure by detecting exploitable vulnerability using CVEs (Common Vulnerabilities and Exposures) machine’s component scanning. Once a vulnerability will be found, VEACH agent will suggest the user (by Web UI) a way to prevent or minimize the vulnerability (when available) and will produce a report representing the overall findings of the scan and preventing methods if available.



**Architecture Diagram**
<br />
<img src="https://user-images.githubusercontent.com/45568925/179365672-e31adfef-84e9-4b7a-ac4e-c540d4c0e741.png" alt="Logo" width="1000" height="500">

<p align="right">(<a href="#top">back to top</a>)</p>

### Built With

The following are the frameworks and npm packages used in the project:

* [Django](https://www.djangoproject.com/) - Backend
* [MongoDB](https://www.mongodb.com/)
* [Ubuntu](https://ubuntu.com/download/desktop) - OS
* [Vue](https://vuejs.org/) - Frontend
* [Vuex](https://vuex.vuejs.org/)
* [Vue Router](https://router.vuejs.org/)
* [Axios](https://axios-http.com/docs/intro)
* [Bootstrap](https://getbootstrap.com/)
* [Chart.js](https://www.chartjs.org/)

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.


## Installation
Install git (If not already installed)
   ```
   sudo apt install git
   ```
Clone the repo
   ```
   git clone https://github.com/omeround3/veach.git
   ```
cd into "veach" folder
   ```
   cd veach
   ```   
   
### Standard Installation
Install system dependencies by running
  ```sh
    xargs sudo apt-get install -y < requirements.system
  ```

Install Python3.9
Update the packages list and install the prerequisites
```
sudo apt update
```
```
sudo apt install software-properties-common
```
Add the deadsnakes PPA to your system’s sources list
```
sudo add-apt-repository ppa:deadsnakes/ppa
```
Once the repository is enabled, you can install Python 3.9 
```
sudo apt install python3.9
```
```
sudo apt-get install python3.9-dev python3.9-venv
```
Create python virutalenv
```
python3.9 -m venv venv
```
Activate python virutalenv
```
source venv/bin/activate
```
Install requirements
```
pip install -r requirements.txt
```

Install MongoDB
Commands are are taken from MongoDB offical docs
* [Install MongoDB on Ubuntu](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/)

Run the commands:
```
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
```
Ubuntu 20.04
```
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
```
Ubuntu 18.04
```
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
```
```
sudo apt-get update
```
```
sudo apt-get install -y mongodb-org
```
```
sudo systemctl daemon-reload
```
```
sudo systemctl start mongod
```
Verify status of mongodb
```
sudo systemctl status mongod
```
if all is ok, enable mongodb to start on system startup
```
sudo systemctl enable mongod
```

Create django superuser
```
python manage.py makemigrations
```
```
python manage.py migrate
```
```
python manage.py createsuperuser_if_none_exists --user=veach --password=veach4Life!
```

Install Node.js and npm
```
sudo apt install curl
```
Enable the NodeSource repository
```
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
```
Once the NodeSource repository is enabled, install Node.js and npm
```
sudo apt install nodejs
```
cd into the frontend directory
```
cd veach_front
```
Install npm packages 
```
npm install
```

Run django server (app backend)
```
python manage.py runserver
```


Open new terminal and run front-end app (default address is http://localhost:8080) 
```
npm run serve
```


If you get a DNS related error from python, follow whese steps:
Install resolvconf from the official repositories
```
sudo apt install resolvconf
```
Start and enable it as follows
```
sudo systemctl start resolvconf.service
```
```
sudo systemctl enable resolvconf.service
```
```
sudo systemctl status resolvconf.service
```
Open the /etc/resolvconf/resolv.conf.d/head configuration file
```
sudo nano /etc/resolvconf/resolv.conf.d/head
```
Aadd the following lines in it
```
nameserver 8.8.8.8 
nameserver 8.8.4.4
```
Save the changes and restart the resolvconf.service and systemd-resolved or reboot the system
```
sudo systemctl restart resolvconf.service
```
```
sudo systemctl restart systemd-resolved.service
```



### Production Installation
#### Installing dependencies**
```
cat requirements.system requirements.prod | sudo xargs apt-get install -y
```
- [] **TODO**



<p align="right">(<a href="#top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage



<p align="right">(<a href="#top">back to top</a>)</p>

<!-- ROADMAP -->
## Roadmap

* [ ] 
* [ ] 
* [ ] 

See the [open issues](https://github.com/omeround3/veach/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

* omeround3@gmail.com
* danielshaal92@gmail.com
* thagag16@gmail.com

Project Link: [https://github.com/omeround3/veach](https://github.com/omeround3/veach)

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* Project inspired by 

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/omeround3/veach.svg?style=for-the-badge
[contributors-url]: https://github.com/omeround3/veach/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/omeround3/veach.svg?style=for-the-badge
[forks-url]: https://github.com/omeround3/veach/network/members
[stars-shield]: https://img.shields.io/github/stars/omeround3/veach.svg?style=for-the-badge
[stars-url]: https://github.com/omeround3/veach/stargazers
[issues-shield]: https://img.shields.io/github/issues/omeround3/veach.svg?style=for-the-badge
[issues-url]: https://github.com/omeround3/veach/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/omeround3/veach/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/omer-lev-ron-a075351b0
