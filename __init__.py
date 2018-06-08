import httplib2
import json
import random
import requests
import string

from flask import Flask, render_template, request, redirect, \
    jsonify, url_for, flash
from flask import make_response
from flask import session as login_session

#import oauth2client.client

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Catalog, CatalogItem, \
    User, select_data

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secres.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Menu Application"

# Connect to Database and create database session
#engine = create_engine('sqlite:///Catalog.db')
# adjust for project6
engine = create_engine('postgresql://catalog:password@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# #########login# ########## ##############
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    SubMenu = showCatalog_SubMenu()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, SubMenu=SubMenu)


# #########fbconnect# ########## ##############
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = '1599054306856805'
    # json.loads(open('fb_client_secres.json', 'r').read())['web']['app_id']
    app_secret = 'ac5aef93149c9b0af49b04b1c64b2688'
    # json.loads(open('fb_client_secres.json', 'r').
    # read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' \
          'grant_type=fb_exchange_token&client_id=%s&' \
          'client_secret=%s&fb_exchange_token=%s' % (
              app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?' \
          'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?' \
          'access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;' \
              'border-radius: 150px;-webkit-border-radius: ' \
              '150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# #########fbdisconnect# ########## ##############
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
          % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# #########gconnect# ########## ##############
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secres.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except oauth2client.client.FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is '
                                            'already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json  # remove ()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# #########createUser# ########## ##############
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# #########getUserInfo# ########## ##############
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# #########getUserID# ########## ##############
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# #########gdisconnect# ########## ##############
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke '
                                            'token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# #########catalogMenuJSON# ########## ##############
@app.route('/catalog/<string:catalog_name>/menu/JSON')
def catalogMenuJSON(catalog_id):
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(CatalogItem).filter_by(
        catalog_id=catalog_id).all()
    return jsonify(CatalogItems=[i.serialize for i in items])


# #########menuItemJSON# ########## ##############
@app.route('/catalog/<string:catalog_name>/menu/<int:menu_id>/JSON')
def menuItemJSON(catalog_id, menu_id):
    Menu_Item = session.query(CatalogItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


# #########catalogsJSON# ########## ##############
@app.route('/catalog/JSON')
def catalogsJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs=[r.serialize for r in catalogs])


# #########show all Catalogs# ########## ##############
# Show all catalogs
@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    catalogs = showCatalog_SubMenu()
    if 'username' not in login_session:
        Latest_Items = select_data()
        return render_template('publiccatalogs.html', catalogs=catalogs,
                               Latest_Items=Latest_Items, SubMenu=catalogs)
    else:
        return render_template('catalogs.html', catalogs=catalogs)


def showCatalog_SubMenu():
    SubMenu = session.query(Catalog).order_by(asc(Catalog.name))
    return SubMenu


# #########create new Catalog# ########## ##############
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCatalog():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCatalog = Catalog(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCatalog)
        flash('New Catalog %s Successfully Created' % newCatalog.name)
        session.commit()
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('newCatalog.html')


# #########edit Catalog# ########## ##############
#  Edit a catalog

@app.route('/catalog/<string:catalog_name>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_name):
    editedCatalog = session.query(
        Catalog).filter_by(name=catalog_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCatalog.user_id != login_session['user_id']:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to edit this catalog." \
               " Please create your own catalog in order to edit." \
               "');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedCatalog.name = request.form['name']
            flash('Catalog Successfully Edited %s' % editedCatalog.name)
            return redirect(url_for('showCatalogs'))
    else:
        return render_template('editCatalog.html', catalog=editedCatalog)


# #########deleteCatalog# ########## ##############
# Delete a catalog
@app.route('/catalog/<string:catalog_name>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalog_name):
    catalogToDelete = session.query(
        Catalog).filter_by(name=catalog_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if catalogToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to delete this catalog." \
               " Please create your own catalog in order to delete.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(catalogToDelete)
        flash('%s Successfully Deleted' % catalogToDelete.name)
        session.commit()
        return redirect(url_for('showCatalogs', catalog_name=catalog_name))
    else:
        return render_template('deleteCatalog.html', catalog=catalogToDelete)


# #########showCatalog# ########## ##############
# Show a catalog menu
@app.route('/catalog/<string:catalog_name>/')
@app.route('/catalog/<string:catalog_name>/menu/')
def showCatalog(catalog_name):
    try:
        catalog = session.query(Catalog). \
            filter_by(name=catalog_name).one()
        creator = getUserInfo(catalog.user_id)
        items = session.query(CatalogItem). \
            filter_by(catalog_id=catalog.id).all()
        SubMenu = showCatalog_SubMenu()
        if 'username' not in login_session or creator.id != \
                login_session['user_id']:
            return render_template('publicmenu.html',
                                   items=items, catalog=catalog,
                                   creator=creator, SubMenu=SubMenu)
        else:
            return render_template('menu.html',
                                   items=items, catalog=catalog,
                                   creator=creator, SubMenu=SubMenu)
    except:
        return render_template('publicmenu.html',
                               items=None, catalog=None,
                               creator=None, SubMenu=None)


# #########editCatalogItem# ########## ##############
# Edit a menu item
@app.route('/showCatalogItem/<string:catalog_name>'
           '/menu/<int:menu_id>', methods=['GET'])
def showCatalogItem(catalog_name, menu_id):
    SubMenu = showCatalog_SubMenu()
    editedItem = session.query(CatalogItem). \
        filter_by(id=menu_id).one()
    print(editedItem)
    return render_template('publicmenuitem.html',
                           catalog_name=catalog_name,
                           menu_id=menu_id, item=editedItem, SubMenu=SubMenu)


# #########newCatalogItem# ########## ##############
# Create a new menu item
@app.route('/catalog/<string:catalog_name>/menu/new/',
           methods=['GET', 'POST'])
def newCatalogItem(catalog_name):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to " \
               "add menu items to this catalog." \
               " Please create your own catalog in " \
               "order to add items.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        print ('create item post')
        newItem = CatalogItem(name=request.form['name'],
                              description=request.form['description'],
                              price=request.form['price'],
                              course=request.form['course'],
                              catalog_id=catalog.id, user_id=catalog.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog', catalog_id=catalog_name))
    else:
        return render_template('newmenuitem.html', catalog_name=catalog_name)


# #########editCatalogItem# ########## ##############
# Edit a menu item
@app.route('/catalog/<string:catalog_name>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editCatalogItem(catalog_name, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(CatalogItem).filter_by(id=menu_id).one()
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to edit menu items " \
               "to this catalog. Please create your own catalog " \
               "in order to edit items.');}" \
               "</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showCatalog',
                                catalog_name=catalog_name))
    else:
        return render_template('editmenuitem.html',
                               catalog_name=catalog_name,
                               menu_id=menu_id, item=editedItem)


# #########deleteCatalogItem# ########## ##############
# Delete a menu item
@app.route('/catalog/<string:catalog_name>/'
           'menu/<int:menu_id>/delete', methods=['GET', 'POST'])
def deleteCatalogItem(catalog_name, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    itemToDelete = session.query(CatalogItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction()" \
               " {alert('You are not authorized to delete menu" \
               " items to this catalog." \
               " Please create your own catalog in order " \
               "to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showCatalog',
                                catalog_name=catalog_name))
    else:
        return render_template('deleteCatalogItem.html', item=itemToDelete)


# #########disconnect# ########## ##############
# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalogs'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalogs'))


# #########main# ########## ##############
if __name__ == '__main__':
    app.secret_key = 'fz_catalog_key'
    app.debug = True
    app.run(host='localhost', port=8000)
