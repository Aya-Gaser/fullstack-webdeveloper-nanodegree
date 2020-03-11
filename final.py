#!/usr/bin/env python3
from flask import Flask, render_template as r_t, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.debug = True
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session

engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# //////////////////////////  START SET FILES FOR NOT REGESTERED USERS

# Show all restaurants PUBLIC
@app.route('/')
@app.route('/restaurants/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    res = restaurants
    if 'username' not in login_session:
        return r_t('publicrestaurants.html', restaurants=res)
    else:
        return r_t('restaurants.html', restaurants=res)


# Show a restaurant menu PUBLIC


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
    except NoResultFound:
        return redirect('/restaurants/')
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    it = items
    res = restaurant
    # check user autherzation
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if 'username' in login_session and login_session['username'] == cm:
        return r_t('menu.html', items=it, restaurant=res, creator=cretor)
    elif 'username' in login_session and login_session['username'] != cm:
        return r_t('notOwner.html', items=it, restaurant=res, creator=cretor)
    else:
        return r_t('publicmenu.html', items=it, restaurant=res, creator=cretor)

# //////////////////////////  END SET FILES FOR NOT REGESTERED USERS

# //////////////////////////  START LOGIN PROCESS
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return r_t('login.html', STATE=state)


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
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
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
        response = make_response(json.dumps(' user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # login_session['user_id']=createUser(login_session)

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    found, something = find_createUser(login_session)
    if(found is False):
        login_session['userid'] = something
        output = ''
        output += '<h1>Welcome '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ''' "style ="width: 300px;height:300px;border-radius:150px;
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''
    else:
        user = something
        login_session['userid'] = user.id
        output = ''
        output += '<h1>Welcome backkkkkkkkk '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ''' "style ="width: 300px;height:300px;border-radius:150px;
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''
    # See if a user exists, if it doesn't make a new one

    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions


def find_createUser(login_session):
    userid = getUserID(login_session['email'])
    if(userid is None):
        newUser = User(name=login_session['username'], email=login_session[
            'email'], picture=login_session['picture'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        return False, user.id
    else:
        user = getUserInfo(userid)
        return True, user


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None

# //////////////////////////  START LOGOUT PROCESS
# # DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    revoke = requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': access_token},
        headers={'content-type': 'application/x-www-form-urlencoded'})
    result = getattr(revoke, 'status_code')
    status_code = getattr(revoke, 'status_code')
    if result == 400 or result == 200:
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
        return r_t('publicrestaurants.html', restaurants=restaurants)
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps(result, 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# //////////////////////////  START RETURN JSON
# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])

# ////////////////////////// START RESTAURANT CRUD
# Create a new restaurant
@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['userid'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return r_t('newRestaurant.html')

# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
    except NoResultFound:
        return redirect('/restaurants/')
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if cm != login_session['username']:
        return redirect('/restaurant/'+str(restaurant_id))
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return r_t('editRestaurant.html', restaurant=editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
    except NoResultFound:
        return redirect('/restaurants/')
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if cm != login_session['username']:
        return redirect('/restaurant/'+str(restaurant_id))
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    # if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))


# //////////////////////////  START MENUITEM CRUD
# Create a new menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/new/',
    methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
    except NoResultFound:
        return redirect('/restaurants/')
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if cm != login_session['username']:
        return redirect('/restaurant/'+str(restaurant_id))
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'], course=request.form['course'],
            restaurant_id=restaurant_id, user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return r_t('newmenuitem.html', restaurant_id=restaurant_id)

# Edit a menu item


@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
    methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
        editedItem = session.query(MenuItem).filter_by(
            restaurant_id=rid, id=menu_id).one()
    except NoResultFound:
        return redirect('/restaurants/')
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if cm != login_session['username']:
        return redirect('/restaurant/'+str(restaurant_id))
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
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return r_t(
            'editmenuitem.html',
            restaurant_id=restaurant_id, menu_id=menu_id,
            item=editedItem)


# Delete a menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
    methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    rid = restaurant_id
    try:
        restaurant = session.query(Restaurant).filter_by(id=rid).one()
        itemToDelete = session.query(MenuItem).filter_by(
            restaurant_id=rid, id=menu_id).one()
    except NoResultFound:
        return redirect('/restaurants/')
    cretor = getUserInfo(restaurant.user_id)
    cm = cretor.name
    if cm != login_session['username']:
        return redirect('/restaurant/'+str(restaurant_id))
        # if request.method == 'POST':
    session.delete(itemToDelete)
    session.commit()
    flash('Menu Item Successfully Deleted')
    return redirect(url_for('showMenu', restaurant_id=restaurant_id))


# //////////////////////////  END MENUITEM CRUD

if __name__ == '__main__':
    
    app.run(host='127.0.0.1:8000')

