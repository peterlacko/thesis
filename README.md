Prototype of client-server application for negotiation of document version
using digital signatures.
Enables users to securely store documents in versions on server, sign documents,
review collaboration history, and more.
Server side is written in python ([Django](https://www.djangoproject.com)),
client side logic in JavaScript ([jQuery](https://jquery.com/), [PKI.js](pkijs.org))
using WebCrypto API.

Steps necessary  for running application on Fedora 23 testing server follow.
For different Fedora versions or GNU/Linux distributions,
same steps will apply, but commands and package names may vary.

Checkout this repository

    git clone https://github.com/peterlacko/thesis

change into `thesis/` directory and continue with next section.

## Vagrant deployment (recommended)
To ease deployment of application in development environment, Vagrantfile that automates installation
and configuration of application in virtualized environment is available.
To use it, you need [Vagrant (1.8.4 or higher) installed on your system](https://www.vagrantup.com/docs/installation/).
After that, simply run

    vagrant up

and continue to Post installation steps.

Note: You can you encounter an error `cannot reconstruct rpm from disk files`, while updating
system packages, which is likely due to the bug in dnf module of ansible.
In that case, run `vagrant provision` or ssh into machine using `vagrant ssh`,
run `sudo dnf update -y` manually and then from host run `vagrant provision`.

## Manual deployment
Update the system, add repository for latest version
of PostgreSQL 9.5, which is necessary for proper application functionality,
and install necessary packages

    sudo dnf update
    sudo rpm -Uvh http://yum.postgresql.org/9.5/fedora/fedora-23-x86_64/pgdg-fedora95-9.5-3.noarch.rpm
    sudo dnf install -y postgresql95-server postgresql95 python3-mod_wsgi python3-psycopg2 python3-pip python3-pyOpenSSL git

and also Django for python 3 using Python Package Installer

    sudo pip3 install django django-formtools django-mathfilters django-phonenumber-field django-two-factor-auth django-extensions

Edit `/var/lib/pgsql/9.5/data/pg_hba.conf` and set authentication method to `trust` for all connections to avoid using
password when manipulating with database (this is not safe and must be turned off in production environment!).

    sudo vim /var/lib/pgsql/9.5/data/pg_hba.conf

Now we need to initialize PostgreSQL database, start its daemon and add
it to programs that run on startup.

    sudo /usr/pgsql-9.5/bin/postgresql95-setup initdb
    sudo systemctl start postgresql-9.5
    sudo systemctl enable postgresql-9.5

Then as a `postgres` user, we need to create user and database, both named `sdv`

    sudo su - postgres
    createuser sdv -lsd
    createdb -O sdv sdv
    exit

Change to `sdv/` directory, run initial database migration and try to run testing server provided by Django

    cd sdv/
    python3 manage.py makemigrations sdvapp
    python3 manage.py migrate
    python3 manage.py runserver 0.0.0.0:8000

If everything goes well, you will see output similar to this

    System check identified no issues (0 silenced).
    May 22, 2016 - 08:53:34
    Django version 1.9.4, using settings 'sdvproject.settings'
    Starting development server on 0.0.0.0:8000
    Quit the server with CONTROL-C.

Now for system to run properly, in `sdvproject/settings.py` we need to
set variable `SECRET_KEY` to secret random string and point
variable `SECRET_KEY_PATH` to directory containing server's certificate and
its respective private key, e.g.

    SECRET_KEY = '2lxvaer87#5czkw5374s=k!-54$yl7seart^uh)1m5_-u1o1bj'
    SECRET_KEY_PATH = '/vagrant/sdv/keys/'

Key files within `SECRET_KEY_PATHSECRET_KEY_PATH` must be named as `certificate_signing_cert.pem` and
`certificate_signing_key.pem`.
We can generate custom self signed certificate by running following command

    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout certificate_signing_key.key -out certificate_signing_cert.crt


## Post installation steps
Login to the machine where application is installed (e.g. if you provisioned over vagrant,
run `vagrant ssh default` from directory containing `Vagrantfile`)
Now create first (super)user of the application,

    python3 manage.py createsuperuser

Run server

    python3 manage.py runserver 0.0.0.0:8000

If everything goes well, you should be able to access system on
http://localhost:8000

For accessing full functionality, it is necessary to perform few more steps:

* login to administration section on http://localhost:8000/admin/ using previously
created user
* create new `Organization`
* create new `User Role`, binding current user and new organization. Make sure that 'can invite'
is checked
* go to http://localhost:8000/invite/ and create new invitation for user
* after submitting invitation, you should see URL to registration form and secret code
* open URL in new tab, enter secret code and finish registration
* now you can login to the system as newly created user, with full functionality available

It is strongly recommended to have WebConsole of the browser opened while using
the system to see info/debug messages and discover potential issues.

## Licensing

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
