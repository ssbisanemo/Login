import os, binascii, hashlib

def hash_password(passwo):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', passwo.encode('utf-8'),
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')
#encrypts password

def verify_password(stored_password, provided_password):
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password
#encrypts given password in same way as stored one and checks if they are the same

def login(ln):
    loc = 0
    use = input('Username: ')
    exists = False
    for i in range(len(ln)):
        if use == ln[i][0]:
            loc = i
            exists = True
    if exists:
        pw = input('Password: ')
        while verify_password(ln[loc][1], pw) is False:
            print('Incorrect Password. Try Again')
            pw = input('Password: ')
        print('Successfully Logged In')
    else:
        print('Invalid Username. Please Try Again')
        login(ln)

def password(pw):
    dg = False
    up = False
    lo = False
    ln = False
    if len(pw) >= 8:
        ln = True
    passw = list(pw)
    for a in passw:
        if a.isdigit() and dg == False:
            dg = True
        elif a.isupper() and up == False:
            up = True
        elif a.islower() and lo == False:
            lo = True

    if dg and up and lo and ln:
        return False
    else:
        if dg is False:
            print('PASSWORD MUST CONTAIN A NUMBER')
        if up is False:
            print('PASSWORD MUST CONTAIN A CAPITAL LETTER')
        if lo is False:
            print('PASSWORD MUST CONTAIN A LOWERCASE LETTER')
        if ln is False:
            print('PASSWORD MUST HAVE AT LEAST 8 CHARACTERS')
        print('\n')
        return True

def new(user, pw, listnm, filename):
    listnm.append([user, hash_password(pw)])
    filename.seek(0)
    filename.truncate(0)
    filename.write(str(listnm))

def create(listname, filename):
    us = input("\nEnter your username here ")
    allowed = True
    for name in range(len(listname)):
        if us == listname[name][0]:
            allowed = False
    #checks if username is valid, and only then lets you enter a password
    if allowed is True:
        pw = input('Enter your password here ')
        while password(pw):
            pw = input('Enter your password here ')
        new(us, pw, listname, filename)
    elif allowed is False:
        print('This username already exists. please choose another one')
        create(listname, filename)

def main():
    with open('usr.txt', 'r+') as n:
        users = eval(n.read())
        ch = int(input("Would you like to \n(1)login or \n(2)create a new account?\n"))
        if ch == 1:
            login(users)
            # TODO: add things to do here once logged in

        elif ch == 2:
            create(users, n)
        else:
            print('Invalid choice, please try again')
            main()

if __name__ == '__main__':
    main()
