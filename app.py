from flask import Flask, render_template, request, url_for, redirect, flash, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
import uuid as uuid
import os
from datetime import timedelta, date
import smtplib
from email.message import EmailMessage

#To run: python -m flask run
app = Flask(__name__)
app.secret_key = 'this is a secret'

#MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_DB'] = 'digicup'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''

mysql = MySQL(app)

#folder config
#maybe create folders for plants and updates
PLANT_FOLDER="static/images/plants/"
UPDATES_FOLDER="static/images/updates"
app.config['UPLOAD_PLANTS'] = PLANT_FOLDER
app.config['UPLOAD_UPDATES'] = UPDATES_FOLDER

UPLOAD_FOLDER="static/images/"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# List of allowed extensions for uploading images
app.config['ALLOWED_IMAGE_EXTENSIONS'] = ["PNG","JPG","JPEG","GIF"]


#This function checks the extension of files that are being uploaded with a list of allowed extensions.
#If the file extension is is within the list, return true
#Else return false 
def allowed_image(filename):
        if not "." in filename:
            return False

        extension = filename.rsplit(".", 1)[1]

        if extension.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
            return True

        else:
            return False

#The htmlspecialchars() function converts some predefined characters to HTML entities.
def htmlspecialchars(text):
    return (
        text.replace("&", "&amp;").
            replace('"', "&quot;").
            replace("<", "&lt;").
            replace(">", "&gt;"))

# Check if user is logged in
# Return true if user session exists
# else return false and redirect user to the login page
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized access! Please login first!')
            return redirect(url_for('login'))
    return wrap

# Check if the admin is logged in
# Return true is admin session exists
# else return false and redirects to admin login page 
def is_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized access! Please login first!')
            return redirect(url_for('admin_login'))
    return wrap


# Default route redirecting user to index page
# Fetching plants information from the database storing it in a variable to be sent to the index.html 
# Renders the index page with the necessary information
@app.route("/")
def index():

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM plants")
    result = cursor.fetchall()
    cursor.close()
    
    return render_template('index.html',result=result)

# The view_details page contains information about specific plants.
# Gets the plant's id via a GET HTTP method
# Uses it to fetch the plants details from the database (Name, picture, quantity etc...)
# Send the data to be displayed when rendering the view_details.html page
@app.route("/view_details", methods=['POST','GET'])
def view_details():

    if request.method == 'GET':

        plant_id = request.args.get('plant_id')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM plants WHERE id=%s", (plant_id,))
        result = cursor.fetchone()
        cursor.close()

    return render_template('view_details.html', result = result)

# The login page contains a form for users to be able to enter their credentials
# On submission, a POST request is made with data email and password of the user.
# The email is looked for in the database, if email does not exist return error message 
# If email exists then retrieve the hashed password from the database and verify that the entered password and the unhashed password are the same
# Create a user session and redirect the user to the home page with a success message
@app.route("/login", methods=['POST', 'GET'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        passwordform = request.form['password']

        cursor = mysql.connection.cursor()
        result = cursor.execute("SELECT * FROM users WHERE email=%s", (email,))

        if result > 0:

            data = cursor.fetchone()
            password = data[1]

            if sha256_crypt.verify(passwordform, password):

                session['logged_in'] = True
                session['email'] = email
                session['fname'] = data[2]
                flash('You are now logged in!')
                return redirect(url_for('index'))

            else:

                flash('Invalid password!')
                return redirect(url_for('login'))

        else:

            flash('Invalid credentials!')
            return redirect(url_for('login'))

    return render_template('login.html')

# Destroy the session 
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out!')
    return redirect(url_for('login'))

# Sends a POST request with all the form values from the register.html page that contains all user information
# The email is cross-checked with the database to verify that it does not already exists.
# If it exists redirect the user to the register page with an error message
# If it does not exist, check that both passwords match and then insert all the user information into the database.
# Then redirect the user to the login page with a success message
@app.route("/register", methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
    
        fname = request.form['first_name']
        lname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        dob = request.form['dob']
        address_1 = request.form['address_1']
        address_2 = request.form['address_2']
        tel_no = request.form['tel_no']
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        account = cursor.fetchone()

        if account: 

            flash("Email already associated with an existing account!")
            return redirect(url_for('register'))

        elif not password == repeat_password:

            flash("Passwords do not match!")
            return redirect(url_for('register'))

        else:

            password_enc = sha256_crypt.encrypt(str(password))
            cursor.execute("INSERT INTO users (email, password, fname, lname, dob, address_1, address_2, tel_no) VALUES (%s, %s, %s, %s, %s ,%s, %s,%s)", (email,password_enc, fname, lname, dob, address_1, address_2, tel_no,))
            mysql.connection.commit()
            flash("User has been created successfully!")
            return redirect(url_for('login'))
        

    return render_template('register.html')

# When the user is logged in, the apply route is then allowed.
# Note: All routes that have the @is_logged_in function attached will require the user to log in to be able to execute
# This takes as input the value in the form found on the view_plant page (plant_id and qty)
# It also fetches the user's email from the session
# A number of application entries will be created in the database (Based on the quantity that the user chose in the form)
# Redirect the user to the home page with a success message
@app.route("/apply", methods=['POST','GET'])
@is_logged_in
def apply():
    if request.method == 'POST':

        plant_id = request.form['plant_id']
        qty = int(request.form['qty'])
        email = session['email']

        cursor = mysql.connection.cursor()
      
        for i in range(qty):
            result = cursor.execute("INSERT INTO applications (email,plant_id) VALUES (%s, %s)", (email, plant_id,))
            mysql.connection.commit()

        
        flash('You have applied!')
        return redirect(url_for('index'))

# Fetches the email of the currently logged in user from session
# Execute database statement to fetch all the applications that is attached to the user email
@app.route('/applications')
@is_logged_in
def applications():

    cursor = mysql.connection.cursor()
    email = session['email']
    cursor.execute("""SELECT plants.plant_name, applications.date, applications.approved 
    FROM applications INNER JOIN plants ON plants.id = applications.plant_id 
    WHERE email=%s""", (email,))

    data = cursor.fetchall()

    
    return render_template('applications.html', data=data)

# Fetches the email of the currently logged in user from the session
# Fetches all the plants and their information that are assigned to that email
# (Use of 2 inner join linking table plants, applications and myplants)
# Send the data to the myplants.html to be displayed
@app.route('/myplants', methods=['GET', 'POST'])
@is_logged_in
def myplants():

    cursor = mysql.connection.cursor()
    email = session['email']
    cursor.execute("""SELECT plants.plant_name,myplants.nickname,plants.image_url, myplants.planted_date, myplants.planted, myplants.app_id, myplants.updated_url
    FROM plants INNER JOIN applications ON plants.id=applications.plant_id 
    INNER JOIN myplants ON myplants.app_id=applications.id
    WHERE email=%s""",(email,))

    data = cursor.fetchall()

    return render_template('myplants.html', plants=data)

# Gets the id, nickname, status and image of plant from a form using POST method
# Checks if the file is in proper format (Check if it is an image and that it is not empty)
# Update the image name and assign a unique name to the image 
# Sends the image into the folder where images are stored on the local machine
# Update the plant's values in the database and save image url of the updated plant
# Redirect the user to myplants page
@app.route('/edit_myplants', methods=['POST', 'GET'])
@is_logged_in
def edit_myplants():
    if request.method == 'POST':
        id = request.form['myplant_id']
        name = request.form['myplant_name']
        planted = request.form.getlist('planted')
        image = request.files['image']
        date_planted = date.today()

        if image.filename == "" :
            flash("No file selected")
            return redirect(url_for('myplants'))

        if not allowed_image(image.filename):
            flash("That image extension is not allowed")
            return redirect(url_for('index'))


        image_url = secure_filename(image.filename)
        image_name = str(uuid.uuid1()) + "_" + image_url

        image.save(os.path.join(app.config['UPLOAD_UPDATES'], image_name))

        cursor = mysql.connection.cursor()


        planted_ = 1
        cursor.execute('UPDATE myplants SET planted=%s, nickname=%s ,updated_url=%s, planted_date=%s WHERE app_id=%s', (planted_, name, image_name ,date_planted,id, ))
        mysql.connection.commit()



        cursor.close()

        return redirect(url_for('myplants'))

# Gets the id, image and comment of the plant from form using POST method
# Checks if the file is in proper format (Check if it is an image and that it is not empty)
# Update the image name and assign a unique name to the image
# Sends the image into the folder where images are stored on the local machine
# Validate the comment to remove all unwanted characters
# Store the update information of the update into the database with the unique image url
# The plant's picture (updated_url) is changed to the image that was just uploaded
# Redirect user to myplants page 
@app.route("/updates", methods=['POST', 'GET'])
def updates():
    if request.method == 'POST':
        image = request.files['update_image']
        comment = request.form['update_comment']
        myplant_id = request.form['myplant_id']

        # image validation
        if image.filename == '':
            flash("No selected files")
            return redirect(url_for('updates'))


        if not allowed_image(image.filename):
            flash("That image extension is not allowed")
            return redirect(url_for('index'))

        # comment validation
        validated_comment = htmlspecialchars(comment)

        image_url = secure_filename(image.filename)
        image_name = str(uuid.uuid1()) + "_" + image_url

        image.save(os.path.join(app.config['UPLOAD_UPDATES'], image_name))

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO updates (myplants_id, comment, update_img_url) VALUES (%s, %s, %s)",
                       (myplant_id, validated_comment, image_name,))
        mysql.connection.commit()

        due_date = date.today() + timedelta(days=30)
        cursor.execute("Update myplants SET update_due_date = %s, updated_url = %s WHERE app_id=%s", (due_date, image_name, myplant_id))
        mysql.connection.commit()

        flash("Update successful!", "success")
        return redirect(url_for('myplants'))

    if request.method == 'GET':
        myplant_id = request.args.get('myplant_id')
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM updates WHERE myplants_id=%s ORDER BY date DESC",(myplant_id,))

        data = cursor.fetchall()
        
        return render_template('updates.html', myplant_id=myplant_id, data=data)

# 
@app.route('/all_updates')
@is_logged_in
def all_updates():
    cursor = mysql.connection.cursor()
    cursor.execute("""
    SELECT * FROM updates 
    """)
    updates = cursor.fetchall()

    email = session['email']
    postArray = []

    for row in updates:
        postid = row[0]
        type = -1

        cursor.execute("SELECT COUNT(*) as cntStatus,type FROM like_unlike WHERE email=%s AND postid=%s", (email, postid,))
        rs1 = cursor.fetchone()
        count_status = rs1[0]

        if count_status > 0:
            type = rs1[1]

        cursor.execute("SELECT COUNT(*) AS cntLikes FROM like_unlike WHERE type=1 and postid=%s", (postid,))
        rs2 = cursor.fetchone()
        total_likes = rs2[0]

        #cursor.execute("SELECT COUNT(*) AS cntUnlikes FROM like_unlike WHERE type=0 and postid=%s", (postid,))
        #rs3 = cursor.fetchone()
        #total_unlikes = rs3[0]

        if type == 1:
            txtcolor = 'color: #ffa449;'
        else:
            txtcolor = ''

        #if type == 0:
        #    txtcolor2 = 'color: #ffa449;'
        #else:
        #    txtcolor2 = ''

        postObj = {
            'id': row[0],
            'img': row[4],
            'title': row[2],
            'content': row[3],
            'total_likes': total_likes,
            #'total_unlikes': total_unlikes,
            'txtcolor': txtcolor
            #'txtcolor2': txtcolor2
            }
        postArray.append(postObj)
    return render_template('all_updates.html', postall=postArray)


@app.route("/likeunlike",methods=["POST","GET"])
def likeunlike():
    
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        email = session['email']
        postid = request.form['postid']
        type = request.form['type']

        cursor.execute("SELECT COUNT(*) AS cntpost FROM like_unlike WHERE postid=%s AND email=%s", (postid, email))
        rscount = cursor.fetchone()
        count = rscount[0]

        if count == 0:
            sql = "INSERT INTO like_unlike(email,postid,type) VALUES(%s, %s, %s)"
            data = (email, postid, type)
            cursor = mysql.connection.cursor()
            cursor.execute(sql, data)
            mysql.connection.commit()

            cur = mysql.connection.cursor()
            cur.execute("SELECT COUNT(*) AS cntLike FROM like_unlike WHERE type=1 AND postid=%s", (postid,))
            rscounttotal = cur.fetchone()
            countlike = rscounttotal[0]

            #cur = mysql.connection.cursor()
            #cur.execute("SELECT COUNT(*) AS cntUnlike FROM like_unlike WHERE type=0 AND postid=%s", (postid,))
            #rscounttotalunlike = cur.fetchone()
            #countUnlike = rscounttotalunlike[0]

            totallikeajax = countlike
            #totalunlikeajax = countUnlike

        else:
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE like_unlike SET type=%s WHERE email=%s AND postid=%s", (type, email, postid))
            mysql.connection.commit()

            cur = mysql.connection.cursor()
            cur.execute("SELECT COUNT(*) AS cntLike FROM like_unlike WHERE type=1 AND postid=%s", (postid,))
            rscounttotal = cur.fetchone()
            countlike = rscounttotal[0]

            #cur = mysql.connection.cursor()
            #cur.execute("SELECT COUNT(*) AS cntUnlike FROM like_unlike WHERE type=0 AND postid=%s", (postid,))
            #rscounttotalunlike = cur.fetchone()
            #countUnlike = rscounttotalunlike[0]
            # print(countUnlike)

            totallikeajax = countlike
            #totalunlikeajax = countUnlike

    return jsonify({"likes": totallikeajax})

# *****************************************************************************
# ---------------------------------- A D M I N -------------------------------
# *****************************************************************************

@app.route("/admin_register", methods=['POST', 'GET'])
def admin_register():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        repeat_password = request.form['repeat_password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE username=%s", (username,))
        account = cursor.fetchone()

        if account:
            flash("Username already associated with an existing account!")
            return redirect(url_for('admin_register'))

        # elif for the validation
        elif not password == repeat_password:
            flash("Passwords do not match!")
            return redirect(url_for('admin_register'))


        else:
            password_enc = sha256_crypt.encrypt(str(password))
            cursor.execute(
                "INSERT INTO admin (username, password) VALUES (%s, %s)",
                (username, password_enc,))
            mysql.connection.commit()
            flash("User has been created successfully!")
            return redirect(url_for('admin_index'))

    return render_template('admin/admin_register.html')


@app.route("/admin_index")
@is_admin_logged_in
def admin_index():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM myplants")
    result = cursor.fetchall()

    cursor.execute("SELECT * FROM applications WHERE approved IS NULL")
    result2 = cursor.fetchall()
    cursor.close()

    return render_template('admin/admin_index.html', result=result, result2=result2)

@app.route("/admin_login", methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        passwordform = request.form['password']

        cursor = mysql.connection.cursor()
        result = cursor.execute("SELECT * FROM admin WHERE username=%s", (username,))

        if result > 0:
            data = cursor.fetchone()
            password = data[1]
            if sha256_crypt.verify(passwordform, password):
                session['admin_logged_in'] = True
                session['username'] = username

                flash('You are now logged in!')

                return redirect(url_for('admin_index'))
            else:
                flash('Invalid password!')
                return redirect(url_for('admin_login'))

        else:
            flash('Invalid credentials!')
            return redirect(url_for('admin_login'))

    return render_template('admin/admin_login.html')

@app.route('/admin_logout')
@is_admin_logged_in
def admin_logout():
    session.clear()
    flash('You are now logged out!')
    return redirect(url_for('admin_login'))

@app.route('/admin_plants', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_plants():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM plants")
    result = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/admin_plants.html', plants=result)

@app.route('/add_plant', methods=['POST', 'GET'])
def add_plant():
    if request.method == 'POST':
        name = request.form['name']
        sci_name = request.form['sci_name']
        description = request.form['description']
        add_qty = request.form['add_qty']
        image = request.files['img_url']

        if image.filename == '':
            flash('No selected file!')
            return redirect(url_for('admin_plants'))

        if not allowed_image(image.filename):
            flash('That image extension is not allowed!')
            return redirect(url_for('admin_plants'))

        image_url = secure_filename(image.filename)
        image_name = str(uuid.uuid1()) + "_" + image_url

        image.save(os.path.join(app.config['UPLOAD_PLANTS'], image_name))

        cursor = mysql.connection.cursor()
        cursor.execute("""
        INSERT INTO plants (plant_name, sci_name, description, qty, image_url) 
        VALUES (%s, %s, %s, %s, %s)""", (name, sci_name, description, add_qty, image_name))
        mysql.connection.commit()

        flash("successful!")

        return redirect(url_for('admin_plants'))

@app.route('/delete/<string:id_data>', methods=['POST', 'GET'])
def delete(id_data):

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM plants WHERE id=%s", (id_data,))
    mysql.connection.commit()

    flash('Plant deleted!')

    return redirect(url_for('admin_plants'))

@app.route('/update', methods=['POST', 'GET'])
def update():
    if request.method == 'POST':
        id = request.form['plant_id']
        qty = request.form['qty']

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE plants set qty=%s WHERE id=%s", (qty, id))

        flash("Quantity updated!")
        mysql.connection.commit()

        return redirect(url_for('admin_plants'))

@app.route('/admin_applications')
@is_admin_logged_in
def admin_applications():
    cursor = mysql.connection.cursor()
    cursor.execute("""SELECT plants.plant_name, applications.date, users.email, applications.id
    FROM users INNER JOIN applications ON users.email = applications.email
    INNER JOIN plants ON applications.plant_id = plants.id 
    WHERE applications.approved IS NULL
    """)

    data = cursor.fetchall()

    return render_template('admin/admin_applications.html', data=data)

@app.route('/admin_deliveries')
@is_admin_logged_in
def admin_deliveries():

    cursor = mysql.connection.cursor()

    cursor.execute("""
    SELECT plants.plant_name, applications.date, users.email, applications.id
    FROM users INNER JOIN applications ON users.email = applications.email
    INNER JOIN plants ON applications.plant_id = plants.id
    WHERE applications.approved = 1 AND applications.received IS NULL
    """)

    data2 = cursor.fetchall()

    return render_template('admin/admin_deliveries.html', data2=data2)

@app.route("/accept", methods=['POST', 'GET'])
def accept():
    if request.method == 'GET':

        app_id = request.args.get('app_id')

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE applications SET approved=1 WHERE id=%s", (app_id,))
        mysql.connection.commit()

        flash("User application has been accepted!", 'success')
        return redirect(url_for('admin_applications'))

@app.route("/reject", methods=['POST', 'GET'])
def reject():
    if request.method == 'GET':

        app_id = request.args.get('app_id')

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE applications SET approved=0 WHERE id=%s", (app_id,))
        mysql.connection.commit()

        flash("User application has been rejected!", 'danger')
        return redirect(url_for('admin_applications'))

@app.route('/received', methods=['POST', 'GET'])
def received():
    if request.method == 'GET':

        app_id = request.args.get('app_id')
        date_received = date.today()
        due_date = date.today() + timedelta(days=15)

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE applications SET received=1 WHERE id=%s", (app_id,))
        mysql.connection.commit()


        cursor.execute("SELECT plant_id FROM applications WHERE id=%s",(app_id,))
        plant_id = cursor.fetchone()

        cursor.execute("UPDATE plants SET qty=qty-1 WHERE plants.id=%s",(plant_id,))


        cursor.execute('''
        INSERT INTO myplants (delivery_date, update_due_date, app_id)
        VALUES (%s, %s, %s)
        ''', (date_received, due_date, app_id,))
        mysql.connection.commit()

        flash('Plant has been added to the user\'s page!', 'success')
        return redirect(url_for('admin_deliveries'))

@app.route("/admin_view_users", methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_users():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT email,fname,lname,address_1,address_2,dob,tel_no FROM users ORDER BY fname ASC")
    results = cursor.fetchall()
    cursor.close()
    return render_template('admin/admin_view_users.html',results=results)


@app.route("/admin_view_myplants", methods=['POST','GET'])
@is_admin_logged_in
def admin_view_myplants():
    global result
    if request.method == 'POST':
        email = request.form['email']
        #print(email)
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT a.id,m.delivery_date,m.planted,m.nickname,p.plant_name,m.updated_url FROM myplants as m INNER JOIN applications as a ON m.app_id=a.id INNER JOIN plants as p on a.plant_id=p.id WHERE a.email=%s",(email,))
        result = cursor.fetchall()
        cursor.close()

        if(result):
            return render_template('admin/admin_view_myplants.html', results = result)
        else:
            flash("This user has not adopted any plants",'danger')
            return redirect(url_for('admin_view_users'))

    else:
       return redirect(url_for('admin_view_users'))


@app.route("/admin_view_updates", methods=['POST','GET'])
@is_admin_logged_in
def admin_view_updates():
    global myresult
    if request.method == 'GET':
        myplant_id = request.args.get('myplant_id')
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT date,comment,update_img_url FROM updates WHERE myplants_id=%s",(myplant_id ,))
        myresult = cursor.fetchall()
        cursor.close()

    
        return render_template('admin/admin_view_updates.html', results = myresult)


def email_alert(subject,body,to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['subject'] = subject
    msg['to'] = to

    user="testnotification285@gmail.com"
    msg['from']=user
    password="uoghsqrxjaarqkzf"


    server=smtplib.SMTP("smtp.gmail.com",587)
    server.starttls()
    server.login(user,password)
    server.send_message(msg)
    server.quit()

@app.route('/notify')
def notify():
        if request.method == 'GET':
            myplant_id = request.args.get('myplant_id')
            current_date = date.today()
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT DISTINCT a.email FROM applications as a INNER JOIN myplants as m on a.id=m.app_id WHERE m.update_due_date < %s",(current_date,))
            myresult = cursor.fetchall()
            cursor.close()

            for x in myresult:
                email_alert("Email Notification","You have not yet updated the staus of your plant.",x[0])

            flash("succesful",'success')
            return redirect(url_for('admin_late_updates'))
            

@app.route("/admin_late_updates", methods=['POST','GET'])
def admin_late_updates():
    if request.method == 'GET':
        current_date = date.today()
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT m.nickname,m.update_due_date,m.updated_url,a.email FROM myplants as m INNER JOIN applications as a on m.app_id=a.id WHERE m.update_due_date < %s",(current_date,))
        myresult = cursor.fetchall()
        cursor.close()
        return render_template('admin/admin_late_updates.html', results = myresult)


if __name__ == '__main__':
    app.run(debug=True)

