# -*- coding: utf-8 -*-
from app_msg import all_msg
from os import listdir, makedirs, remove
from os.path import join, isdir, splitext, isfile
from time import time, strftime
from base64 import b64encode, b64decode
from hashlib import sha1
from shutil import copytree, rmtree
from fnmatch import fnmatch
from flask import Flask, request, session, g, redirect, abort, render_template, flash, send_from_directory
from flask_mail import Mail, Message
from flask_sslify import SSLify
from Crypto import Random
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename
from pymysql import connect

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

app = Flask(__name__)
app.config.from_object('config')
mail = Mail(app)
if not app.config['DEBUG']:
  sslify = SSLify(app)

def err(txt):
  flash(txt,'err')

def suc(txt):
  flash(txt,'suc')

def is_allowed_file(filename):
  return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.teardown_appcontext
def close_db(error):
  if hasattr(g, 'db_cnx'):
    g.db_cnx.close()

def get_db_cursor():
  cnx = getattr(g, 'db_cnx', None)
  if cnx is None:
    cnx = g.db_cnx = connect(database=app.config['DB'], user=app.config['DB_USERNAME'], password=app.config['DB_PASSWORD'], host=app.config['DB_HOST'])
  cur = cnx.cursor() #buffered=True
  return cur

def get_one(str_sql, arr_val=[]):
  cur = get_db_cursor()
  cur.execute(str_sql, arr_val)
  if cur:
    row = cur.fetchone()
    cur.fetchall() #Flush
    return row
  return None

def get_all(str_sql, arr_val=[]):
  cur = get_db_cursor()
  cur.execute(str_sql, arr_val)
  if cur:
    return cur.fetchall()
  return None

def set_db(str_sql, arr_val=[]):
  cur = get_db_cursor()
  cur.execute(str_sql, arr_val)
  g.db_cnx.commit()

def get_random_password(email):
  return sha1(email+str(time())).hexdigest()[:8]

def get_arr_flag(email):
  row = get_one('select flag from usr where email = %s', [email])
  if row:
    flag = row[0]
    return (flag.split(',') if flag else [])
  return None

def get_lng(email):
  row = get_one('select lng from usr where email = %s', [email])
  if row:
    return row[0]
  return 'en'

def set_fnt(lng):
  session['fnt'] = ('cyrillic' if lng == 'ru' else 'roman')
  return None

def get_all_msg(email):
  return all_msg(get_lng(email))

def get_all_msg_from_session():
  try:
    ret = session['lng']
  except: #session['lng'] does not exist
    ret = 'en'
  return all_msg(ret)

def param_str():
  return ('?disable_cache=%d' % int(time()) if app.config['DISABLE_CACHE'] else '')

def render_template_0(url): #Uses session to determine language
  return render_template(url, app_name = app.config['APP_NAME'], m = get_all_msg_from_session(), p = param_str())

def render_template_1(url, email): #Uses logged-in email to determine language
  return render_template(url, m = get_all_msg(email), p = param_str())

def encrypt(raw):
  bs = AES.block_size
  pad = lambda s: s + (bs - len(s.encode('utf8')) % bs) * chr(bs - len(s.encode('utf8')) % bs)
  raw = pad(raw)
  iv = Random.new().read(AES.block_size)
  cipher = AES.new('this-here-is-key', AES.MODE_CBC, iv)
  return b64encode(iv + cipher.encrypt(raw)).replace('/','_')

def decrypt(enc):
  enc = b64decode(enc.replace('_','/'))
  unpad = lambda s : s.decode('utf8')[0:-ord(s.decode('utf8')[-1])]
  cipher = AES.new('this-here-is-key', AES.MODE_CBC, enc[:16])
  return unpad(cipher.decrypt(enc[16:]))

def authenticate(email, password):
  row = get_one('select password from usr where email = %s', [email])
  return row and password == decrypt(row[0])

def email_password(email, password):
  txt = Message('requested code', recipients=[email])
  txt.html = txt.body = password
  mail.send(txt)
  suc('email sent containing your password')

def avatar_path(email):
  pth_fdr = join(app.config['STATIC_FOLDER'],email)
  for filename in listdir(pth_fdr):
    if fnmatch(filename, 'avatar.*'):
      return join(pth_fdr,filename)
  return None

def delete_avatar(email):
  pth_fdr = join(app.config['STATIC_FOLDER'],email)
  for filename in listdir(pth_fdr):
    if fnmatch(filename, 'avatar.*'):
      remove(join(pth_fdr,filename))
  return None

@app.route('/log_in', methods=['GET', 'POST'])
def log_in():
  if request.method == 'POST':
    session['logged_in'] = authenticate(request.form['email'], request.form['password'])
    if session['logged_in']:
      session['email'] = request.form['email']
      row = get_one('select name,lng from usr where email = %s', [session['email']])
      session['name'] = row[0]
      try:
        set_db('update usr set lng = %s where email = %s', [session['lng'],session['email']])
      except: #session['lng'] does not exist
        session['lng'] = row[1]
      # suc('logged in')
      return redirect('')
    else:
      err('invalid email or password')
  return render_template_0('account/log_in.html')

@app.route('/log_out')
def log_out():
  session.pop('logged_in', None)
  suc('logged out')
  return redirect('')

@app.route('/register', methods=['GET', 'POST'])
def register():
  if request.method == 'POST':
    email = request.form['email']
    row = get_one('select email from usr where email = %s', [email])
    if row:
      err('account already exists')
    else:
      session['name'] = email.split('@')[0]
      password = get_random_password(email)
      set_db('insert into usr values (null,%s,%s,%s,null,"en",0,0,0,null)', [session['name'],email,encrypt(password)])
      try:
        copytree(join(app.config['STATIC_FOLDER'],'default'), join(app.config['STATIC_FOLDER'],email))
      except:
        pass
      email_password(email, password)
      return redirect('')
  return render_template_0('account/register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
  if request.method == 'POST':
    email = request.form['email']
    row = get_one('select password from usr where email = %s', [email])
    if row:
      email_password(email, decrypt(row[0]))
      return redirect('')
    else:
      err('account not found')
  return render_template_0('account/forgot_password.html')

@app.route('/change_name', methods=['GET', 'POST'])
def change_name():
  try:
    email = session['email']
  except:  
    return redirect('')
  if request.method == 'POST':
    if authenticate(email, request.form['password']):
      session['name'] = request.form['new_name']
      set_db('update usr set name = %s where email = %s', [session['name'],email])
      suc('name changed')
    else:  
      err('invalid password')
  return render_template_1('account/change_name.html', email)

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
  try:
    email = session['email']
  except:  
    return redirect('')
  if request.method == 'POST':
    if request.form['new_email'] == request.form['confirm_new_email']:
      if authenticate(email, request.form['password']):
        password = get_random_password(email)
        set_db('update usr set email = %s, password = %s where email = %s', [request.form['new_email'],encrypt(password),email])
        suc('email changed')
        suc('password changed')
        email_password(request.form['new_email'], password)
      else:  
        err('invalid password')
    else:
      err('email addresses do not match')
  return render_template_1('account/change_email.html', email)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
  try:
    email = session['email']
  except:  
    return redirect('')
  if request.method == 'POST':
    if request.form['new_password'] == request.form['confirm_new_password']:
      if authenticate(email, request.form['old_password']):
        set_db('update usr set password = %s where email = %s', [encrypt(request.form['new_password']),email])
        suc('password changed')
      else:  
        err('invalid password')
    else:
      err('passwords do not match')
  return render_template_1('account/change_password.html', email)

@app.route('/language/<lng>')
def language(lng):
  try:
    session['logged_in']
    return redirect('set_lng/' + lng)
  except: #Logged out
    session['lng'] = lng
    return redirect('')

@app.route('/set_lng/<lng>')
def set_lng(lng):
  try:
    email = session['email']
  except:  
    return redirect('')
  session['lng'] = lng
  set_fnt(lng)
  set_db('update usr set lng = %s where email = %s', [lng,email])
  return redirect('change_language')

@app.route('/change_language')
def change_language():
  try:
    session['logged_in']
    try:
      email = session['email']
    except:  
      return redirect('')
    return render_template_1('account/change_language.html', email)
  except: #not logged in
    return redirect('')

@app.route('/<email>/<filename>')
def uploaded_file(email, filename):
  return send_from_directory(join(app.config['UPLOAD_FOLDER'],email), filename)

@app.route('/upload_avatar', methods=['GET', 'POST'])
def upload_avatar():
  try:
    email = session['email']
  except:  
    return redirect('')
  if request.method == 'POST':
    if authenticate(email, request.form['password']):
      if 'file' not in request.files:
        err('no file selected')
        return redirect(request.url)
      file = request.files['file']
      if file.filename == '':
        err('no file selected')
        return redirect(request.url)
      if file and is_allowed_file(file.filename):
        filename = secure_filename(file.filename)
        pth_fdr = join(app.config['UPLOAD_FOLDER'],email)
        try:
          makedirs(pth_fdr)
        except OSError:
          if not isdir(pth_fdr):
            raise
        basename,ext = splitext(filename)
        filename = 'avatar.' + strftime('%Y%m%d%H%M%S') + ext
        pth = join(pth_fdr,filename)
        delete_avatar(email)
        file.save(pth)
      # file.close()
    else:
      err('invalid password')
  return render_template('account/upload_avatar.html', pth = avatar_path(email), m = get_all_msg(email), p = param_str())

@app.route('/toggle_flag/<flag>')
def toggle_flag(flag):
  arr_flag = get_arr_flag(session['email'])
  str_arr_flag = ''
  if flag in arr_flag:
    arr_flag.remove(flag)
    str_arr_flag = ','.join(arr_flag)
  else:
    arr_flag += [flag]
    str_arr_flag = ','.join(arr_flag)
  set_db('update usr set flag = %s where email = %s', [str_arr_flag,session['email']])
  return redirect('choose_flag#flag-display')

@app.route('/choose_flag')
def choose_flag():
  try:
    email = session['email']
  except:
    return redirect('')
  return render_template('account/choose_flag.html', all_flag = sorted(listdir(join(app.config['STATIC_FOLDER'],'flag'))), arr_flag = get_arr_flag(email), m = get_all_msg(email), p = param_str())

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
  try:
    email = session['email']
  except:  
    return redirect('')
  if request.method == 'POST':
    if authenticate(email, request.form['password']):
      if get_all_msg(email)['type these words: delete this account'].split(':')[1][1:] == request.form['type_these_words_delete_this_account']:
        set_db('delete from usr where email = %s', [email])
        pth_fdr = join(app.config['STATIC_FOLDER'],email)
        rmtree(pth_fdr, ignore_errors=True)
        suc('account deleted')
        return redirect('log_out')
      else:
        err('text incorrect')      
    else:
      err('invalid password')
  return render_template_1('account/delete_account.html', email)  

@app.route('/clear')
def clear():
  session.clear()
  session['cleared'] = True
  return redirect('main')

@app.route('/')
def index():
  lng_guess=request.headers['Accept-Language'].split(';')[0].split(',')[0].split('-')[0]
  if not lng_guess:
    lng_guess='en'
  print request.headers['Host']
  try:
    set_fnt(session['lng'])
  except: #session['lng'] does not exist
    set_fnt(lng_guess)
    session['lng'] = lng_guess
  print 'SES',
  for key in session:
    print key, session[key], '|',
  print
  print 'USR',
  try:
    row = get_one('select rowid,* from usr where email = %s', [session['email']])
    for key in row:
      print key, '|',
  except:
    pass
  print
  return render_template('index.html')

@app.route('/main', methods=['GET', 'POST'])
def main():
  try:
    email = session['email']
  except:  
    return redirect('')
  return render_template('main.html', app_name = app.config['APP_NAME'], m = get_all_msg(email), p = param_str())

@app.errorhandler(500)
def internal_error(error):
  try:
    session['cleared']   
    session.pop('cleared', None)
    return 'An error occurred! The administrator has been informed'
  except: #Clear session and try again
    return redirect('clear')

if __name__ == '__main__':
  if not app.config['DEBUG']:
    import logging
    from logging.handlers import SMTPHandler
    mail_handler = SMTPHandler(
                     mailhost=(app.config['MAIL_SERVER'],25),
                     fromaddr=app.config['MAIL_DEFAULT_SENDER'],
                     toaddrs=[app.config['ADMIN_EMAIL']],subject='error',
                     credentials=(app.config['MAIL_USERNAME'],app.config['MAIL_PASSWORD']))
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)
  app.run()
