# clair-report
clair-scanner is a convenient tools for local docker image scan with white-list, but we have no idea what CVEs are impactive from the scanned results, also, you may need search CVE-IDs on Internet to get CVE-IDs details.
In order to solve above problems, clair-report is a python script which helps you generate simple web reports by using [clair-scanner](https://github.com/arminc/clair-scanner), [nginx](https://hub.docker.com/r/library/nginx/) and [pelican](http://docs.getpelican.com/en/stable/#). You can get the level of impact and details from [Red Hat CVE Database](https://access.redhat.com/security/security-updates/#/cve) via the web reports quickly.

Do the following steps to install essential packages and set up an executable environment on baremetel.

## 1. Install pip and docker
If you've set locale all, please ignore the first command shows below.
```
export LC_ALL=C
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install -y python-pip python-dev
curl -fsSL "https://get.docker.com/" | sh
sudo pip install -U pip docker-py
```

## 2. Install Go programming language
You can find go release versions from [release history]（https://golang.org/doc/devel/release.html）, and download the version you like.
```
wget https://storage.googleapis.com/golang/go1.9.2.linux-amd64.tar.gz
sudo tar -xzf go1.9.2.linux-amd64.tar.gz -C /usr/local
```

Setting up go environment, modify /etc/profile, and add followings into the bottom.
```
export GOROOT=/usr/local/go
export GOBIN=$GOROOT/bin
export PATH=$PATH:$GOBIN
export GOPATH=$HOME/go
```
source the configuration.
```
source /etc/profile
```

## 3. Install clair-scanner
Move to go work file(e.g. /root/go/src), clone clair-scanner and build clair-scanner by go.
```
cd /root/go/src/
git clone https://github.com/arminc/clair-scanner.git
make ensure && make build
make cross
```
If error message shows no dep, please run the following command.
```
go get -u github.com/golang/dep/cmd/dep
```

## 4. Run docker nginx
Move to clair-scanner folder, and run nginx service by docker
```
cd /root/go/src/clair-scanner
docker run -it -p 8080:80 -v `pwd`/www/output:/usr/share/nginx/html -v `pwd`/logs:/var/log/nginx -d nginx
```

## 5. Install pelican
Do the following command in clair-scanner folder
```
cd www
pip install pelican markdown
pelican-quickstart
```
Setting up pelican will ask you some questions, such like below.
```
> Where do you want to create your new web site? [.] 
> What will be the title of this web site? Clair Report            
> Who will be the author of this web site? Argon
> What will be the default language of this web site? [English] 
> Do you want to specify a URL prefix? e.g., http://example.com   (Y/n) n
> Do you want to enable article pagination? (Y/n) y
> How many articles per page do you want? [10] 
> What is your time zone? [Europe/Paris] Asia/Taipei
> Do you want to generate a Fabfile/Makefile to automate generation and publishing? (Y/n) y
> Do you want an auto-reload & simpleHTTP script to assist with theme and site development? (Y/n) y
> Do you want to upload your website using FTP? (y/N) n
> Do you want to upload your website using SSH? (y/N) y
> What is the hostname of your SSH server? [localhost] clair-scanner
> What is the port of your SSH server? [22] 
> What is your username on that server? [root] 
> Where do you want to put your web site on that server? [/var/www] /root/go/src/clair-scanner/www
> Do you want to upload your website using Dropbox? (y/N) n
> Do you want to upload your website using S3? (y/N) n
> Do you want to upload your website using Rackspace Cloud Files? (y/N) n
> Do you want to upload your website using GitHub Pages? (y/N) n
```

## Use clair-report
Run the scrip in clair-scanner folder.
```
git clone https://github.com/argonmist/clair-report.git
mv clair-report/* ./
python clair-report.py --ip YOUR-HOST-IP --image DOCKER-IMAGE-NAME
```
Go to YOUR-HOST-IP:8080, you'll see the report(you can [chage the template](http://www.pelicanthemes.com/) you like).
