import os, binascii, hashlib
import tkinter as t

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

def log2(entry):
    loc = 0
    exists = False
    use = entry.get()
    for i in range(len(users)):
        if use == users[i][0]:
            loc = i
            exists = True
    if exists:
        passw = t.Entry(win, show="*", background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                        highlightcolor='#00ff00')
        p = t.Label(win, text='Password:', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        ent = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                       activeforeground='#ff00ff',
                       activebackground='#00ff00',
                       font=("Helvetica", 14),
                       command=lambda: [ent.place_forget(),
                                        logi3(loc, passw)])
        win.bind("<Return>", lambda event: [ent.place_forget(),
                                        logi3(loc, passw)])
        p.place(x=63, y=(h/2)-19)
        passw.place(x=140, y=(h / 2)-20)
        ent.place(x=160, y=(h/2)+10)
        passw.focus()

        obj.append(passw)
        obj.append(p)
        obj.append(ent)
    else:
        inv = t.Label(win, text='Invalid Username. Please Try Again', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        us = t.Entry(win, background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                     highlightcolor='#00ff00')
        u = t.Label(win, text='Username:', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        ent = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                       activeforeground='#ff00ff',
                       activebackground='#00ff00',
                       font=("Helvetica", 14),
                       command=lambda: [ent.place_forget(),
                                        inv.place_forget(),
                                        log2(us)])
        win.bind("<Return>", lambda event:[ent.place_forget(),
                                    inv.place_forget(),
                                    log2(us)])
        ent.place(x=160, y=(h / 2) - 30)
        u.place(x=60, y=(h / 2) - 59)
        inv.place(x=70, y=(h/2))
        us.place(x=140, y=(h / 2) - 60)
        us.focus()

        obj.append(us)
        obj.append(u)

def logi3(loc, ent):
    pw = ent.get()
    ent.place_forget()
    i = t.Label(win, text='Incorrect Password. Please Try Again', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    obj.append(i)
    passw = t.Entry(win, show="*", background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                        highlightcolor='#00ff00')
    ent = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                   activeforeground='#ff00ff',
                   activebackground='#00ff00',
                   font=("Helvetica", 14),
                   command=lambda: [ent.place_forget(),
                                    logi3(loc, passw)])

    if verify_password(users[loc][1], pw) is False:
        passw.place(x=140, y=(h / 2) - 20)
        passw.focus()
        ent.place(x=160, y=(h/2)+10)
        i.place(x=70, y=(h/2)+40)
        win.bind("<Return>", lambda event: [ent.place_forget(),
                                    logi3(loc, passw)])
    else:
        for l in obj:
            l.place_forget()
        win.unbind("<Return>")
        suc = t.Label(win, text='Login Successful!', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        suc.place(x=(w/2), y=(h/2)-10, anchor='center')

def login():
    us = t.Entry(win, background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                  highlightcolor='#00ff00')
    us.place(x=140, y=(h / 2) - 60)
    u = t.Label(win, text='Username:', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    u.place(x=60, y=(h / 2) - 59)
    ent = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                      activeforeground='#ff00ff',
                      activebackground='#00ff00',
                      font=("Helvetica", 14),
                      command=lambda: [ent.place_forget(),
                                       log2( us)])
    win.bind("<Return>", lambda event: [ent.place_forget(),
                                       log2( us)])
    ent.place(x=160, y=(h/2)-30)
    us.focus()
    win.update()
    obj.append(us)
    obj.append(u)

def password(user, ent):
    pw = ent.get()
    dg = False
    up = False
    lo = False
    ln = False
    bl = False
    eight = t.Label(win, text='PASSWORD MUST HAVE AT LEAST 8 CHARACTERS',
                    fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    lowe = t.Label(win, text='PASSWORD MUST CONTAIN A LOWERCASE LETTER',
                   fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    caps = t.Label(win, text='PASSWORD MUST CONTAIN A CAPITAL LETTER',
                   fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    num = t.Label(win, text='PASSWORD MUST CONTAIN A NUMBER',
                  fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    bla = t.Label(win, text='PASSWORD MUST NOT BE BLANK',
                  fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    if len(pw) >= 8:
        ln = True
    if pw != "":
        bl = True
    passw = list(pw)
    for a in passw:
        if a.isdigit() and dg is False:
            dg = True
        elif a.isupper() and up is False:
            up = True
        elif a.islower() and lo is False:
            lo = True


    if dg and up and lo and ln and bl:
        new(user, pw)
        win.unbind("<Return>")
        suc = t.Label(win, text='Account Creation Successful!\nPress Enter to Login', fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        suc.place(x=(w / 2), y=(h / 2) - 10, anchor='center')
        win.bind('<Return>', lambda event: [suc.place_forget(),
                                            win.unbind("<Return>"),
                                            start_login(filrname)])
    else:
        pw1 = t.Entry(win, show='*', background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                      highlightcolor='#00ff00')
        la = t.Label(win, text='Enter your Password here',
                     fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        but = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                       activeforeground='#ff00ff',
                       activebackground='#00ff00',
                       font=("Helvetica", 14),
                       command=lambda: [la.pack_forget(),
                                        pw1.pack_forget(),
                                        but.pack_forget(),
                                        num.pack_forget(),
                                        caps.pack_forget(),
                                        lowe.pack_forget(),
                                        eight.pack_forget(),
                                        bla.pack_forget(),
                                        password(user, pw1)])
        win.bind("<Return>", lambda event: [la.pack_forget(),
                                        pw1.pack_forget(),
                                        but.pack_forget(),
                                        num.pack_forget(),
                                        caps.pack_forget(),
                                        lowe.pack_forget(),
                                        eight.pack_forget(),
                                        bla.pack_forget(),
                                        password(user, pw1)])
        la.pack(pady=3)
        pw1.pack()
        but.pack()
        pw1.focus()
        if dg is False:
            num.pack()
        if up is False:
            caps.pack()
        if lo is False:
            lowe.pack()
        if ln is False:
            eight.pack()
        if bl is False:
            bla.pack()

def new(user, pw):
    users.append([user, hash_password(pw), usridentity[-1]+1])
    with open(filrname, 'w') as wr:
        wr.write(str(users))

def create(inv):
    inva = t.Label(win, text='This username already exists. Please choose another one',
                fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    us = t.Entry(win, background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                  highlightcolor='#00ff00')
    la = t.Label(win, text='Enter your Username here',
                fg='#00ff00', bg='#000000', font=("Helvetica", 15))
    but = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                  activeforeground='#ff00ff',
                  activebackground='#00ff00',
                  font=("Helvetica", 14),
                  command=lambda: [la.pack_forget(),
                                   us.pack_forget(),
                                   but.pack_forget(),
                                   inva.place_forget(),
                                   chek(us)])
    win.bind('<Return>', lambda event:[la.pack_forget(),
                                   us.pack_forget(),
                                   but.pack_forget(),
                                   inva.place_forget(),
                                   chek(us)])
    la.pack(pady = 3)
    us.pack()
    us.focus()
    but.pack()
    if inv:
        inva.place(x=(w/2), y=110, anchor = 'center')

def chek(ent):
    us = ent.get()
    allowed = True
    for name in range(len(users)):
        if us == users[name][0]:
            allowed = False
    #checks if username is valid, and only then lets you enter a password
    if us == "":
        create(True)
    elif allowed:
        pw = t.Entry(win, show='*', background='#868686', foreground='#00ff00', highlightbackground='#00ff00',
                     highlightcolor='#00ff00')
        la = t.Label(win, text='Enter your Password here',
                     fg='#00ff00', bg='#000000', font=("Helvetica", 15))
        but = t.Button(win, text='Enter', fg='#00ff00', highlightbackground='#000000',
                       activeforeground='#ff00ff',
                       activebackground='#00ff00',
                       font=("Helvetica", 14),
                       command=lambda: [la.pack_forget(),
                                        pw.pack_forget(),
                                        but.pack_forget(),
                                        password(us, pw)])
        win.bind('<Return>', lambda event:[la.pack_forget(),
                                        pw.pack_forget(),
                                        but.pack_forget(),
                                        password(us, pw)])
        la.pack(pady=3)
        pw.pack()
        but.pack()
        pw.focus()
    else:
        create(True)

def main():
    global win
    win = t.Tk()
    win.title('Login')
    win.geometry(str(w)+'x'+str(h)+'+1200+300')
    win.resizable(False, False)
    win['bg'] = '#000000'
    l = t.Label(win, text='Choose an option',
                fg='#00ff00', bg='#000000', font=("Helvetica", 17))
    log = t.Button(win, text='1. Login', fg='#0000ff', highlightbackground='#000000',
                  activeforeground='#ff00ff',
                  font=("Helvetica", 15),
                  command=lambda: [l.pack_forget(),
                                   log.place_forget(),
                                   crea.place_forget(),
                                   win.unbind("1"),
                                   win.unbind("2"),
                                   login()])
    win.bind("1", lambda event:[l.pack_forget(),
                                log.place_forget(),
                                crea.place_forget(),
                                win.unbind("1"),
                                win.unbind("2"),
                                login()])
    crea = t.Button(win, text='2. Create\naccount', fg='#0000ff', highlightbackground='#000000',
                   activeforeground='#ff00ff',
                   font=("Helvetica", 15),
                   command=lambda: [l.pack_forget(),
                                    log.place_forget(),
                                    crea.place_forget(),
                                    win.unbind("1"),
                                    win.unbind("2"),
                                    create(False)])
    win.bind("2", lambda event:[l.pack_forget(),
                                log.place_forget(),
                                crea.place_forget(),
                                win.unbind("1"),
                                win.unbind("2"),
                                create(False)])
    l.pack(pady=17)
    log.place(anchor='center', x=(w/2)-50, y=80)
    crea.place(anchor='center', x=(w / 2)+50, y=80)

    win.mainloop()

def start_login(filename):
    global h
    global w
    global win
    global obj
    global users
    global usridentity
    global filrname
    filrname = filename
    h = 200
    w= 400
    obj = []
    win = None
    usridentity = []
    with open(filename, 'r') as n:
        users = eval(n.read())
        for i in range(len(users)):
            usridentity.append(users[i][2])
    if not usridentity:
        usridentity = [-1]
    main()


if __name__ == '__main__':
    start_login('usr.txt')

# TODO: add things to do once logged in