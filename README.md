## About project

Application that provides a list of Restaurants within a variety of Menu Items as well as provide a user registration and authentication system via google plus. Registered users will have the ability to create, edit and delete their own Restaurants and items.




# Prepare software and data

**The virtual machine**
This project makes use of the same Linux-based virtual machine (VM) 

1- download and install  Vagrant [here](https://www.vagrantup.com/) and VirtualBox [here](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)

2- Use a terminal : Mac or Linux system, your regular terminal program will do just fine.
   On Windows, we recommend using the Git Bash terminal that comes with the Git software. 
   // download Git from [here](https://git-scm.com/downloads)
3- Install VirtualBox

4- Install Vagrant : then try command `vagrant --version`on terminal 
  //Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem.
 
5- Download the VM configuration : 
   run command :

     git clone https://github.com/udacity/fullstack-nanodegree-vm

7- Start the virtual machine
  run commands :  `vagrant up` then run `vagrant ssh`
  
  ** if `vagrant ssh` : didn't work and told you "must run (vagrant up) first 
    >> then run  `chcp.com 1252` ,
     >>then run `vagrant up`  and  `vagrant ssh` again and you should see
 
 8-  `cd / vagrant`


**Prepare Googlle API**
 1- go to [https://console.developers.google.com/](https://console.developers.google.com/)
 2- create project
 3- in # Credentials tab :  *create oAuth client Id* 
 4-  put the client id in login.html file in line 17 
 

    client_id:  'YOUR-CLIENT-ID.apps.googleusercontent.com'

 5- Edit the created client : 
  add : `http://localhost:5000` in  **Authorized JavaScript origins**
  add : `http://localhost:5000/retaurants` in **Authorized redirect URIs**
 
# How to run

 1-Run provided python files  `python database_setup.py` to create database then `python lotsofmenus.py`  and insert data
2- run application file `python final.py`
3- open [http://localhost:5000/](http://localhost:5000/) in browser
*Finally Enjoy navigating the app !* 

**@aya_gaser**
