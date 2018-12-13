#!/usr/bin/env python

from flask import Flask, render_template, request, \
                  redirect, jsonify, url_for, flash

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CatalogItem, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogitemswithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


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
        response = make_response(json.dumps(
                   'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
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
    output += ' " style = "width: 300px; height: 300px;border-radius: \
            150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    print ('In gdisconnect access token is %s', access_token)
    print ('User name is:')
    print (login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        print 'going to delete session'
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/catalog/JSON')
def catalogItemsJSON():
    items = session.query(CatalogItem).order_by(
            asc(CatalogItem.category_id)).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category_name>/<item_name>/JSON')
def viewItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CatalogItem).filter_by(
            name=item_name, category_id=category.id).one()
    return jsonify(item=item.serialize)


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategory():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(CatalogItem).order_by(
            desc(CatalogItem.id)).limit(10).all()
    item_categories = {}
    for item in items:
        item_category = session.query(Category).filter_by(
                        id=item.category_id).one()
        item_categories[item.name] = item_category.name
    return render_template('categories.html',
                           categories=categories, items=items,
                           item_categories=item_categories,
                           session=login_session)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategory'))
    else:
        return render_template('newCategory.html')


# Show items in a category
@app.route('/catalog/<category_name>/items/')
def catalogItems(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(CatalogItem).filter_by(category_id=category.id).all()
    return render_template('catalogitems.html', session=login_session,
                           catalog_name=category_name,
                           categories=categories, items=items)


# Edit a category
@app.route('/category/<category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(
        name=category_name).one()
    if login_session['user_id'] == editedCategory.user_id:
        if request.method == 'POST':
            if request.form['name']:
                editedCategory.name = request.form['name']
                session.commit()
                flash('Category Successfully Edited %s' % editedCategory.name)
                return redirect(url_for('catalogItems',
                                session=login_session,
                                category_name=editedCategory.name))
        else:
            return render_template('editCategory.html',
                                   session=login_session,
                                   category=editedCategory)
    else:
        return render_template('error.html')


# Delete a category
@app.route('/category/<category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()
    if login_session['user_id'] == categoryToDelete.user_id:
        if request.method == 'POST':
            session.delete(categoryToDelete)
            session.commit()
            flash('Category %s Successfully Deleted' % categoryToDelete.name)
            return redirect(url_for('showCategory'))
        else:
            return render_template('deleteCategory.html',
                                   session=login_session,
                                   category=categoryToDelete)
    else:
        return render_template('error.html')


# Show Item details
@app.route('/catalog/<category_name>/<item_name>/')
def oneItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(CatalogItem).filter_by(
                name=item_name, category_id=category.id).one()
    return render_template('item.html',
                           session=login_session,
                           item=item, category_name=category.name)


# Create a new item in a category
@app.route('/category/<category_name>/item/new/', methods=['GET', 'POST'])
def newItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        newItem = CatalogItem(
                name=request.form['name'],
                description=request.form['description'],
                category_id=category.id,
                user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % newItem.name)
        return redirect(url_for('catalogItems',
                        session=login_session,
                        category_name=category_name))
    else:
        return render_template('newitem.html',
                               session=login_session,
                               category_name=category.name)


# Edit an item
@app.route('/category/<category_name>/<item_name>/edit/',
           methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(CatalogItem).filter_by(name=item_name).one()
    if login_session['user_id'] == editedItem.user_id:
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
            flash('Menu Item Successfully Edited')
            return redirect(url_for('oneItem',
                            session=login_session,
                            category_name=category_name,
                            item_name=editedItem.name))
        else:
            return render_template('edititem.html',
                                   session=login_session,
                                   item=editedItem,
                                   category_name=category_name)
    else:
        return render_template('error.html')


# Delete an item
@app.route('/category/<category_name>/<item_name>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(CatalogItem).filter_by(name=item_name).one()
    if login_session['user_id'] == itemToDelete.user_id:
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            flash('Menu Item Successfully Deleted')
            return redirect(url_for('catalogItems',
                                    session=login_session,
                                    category_name=category_name))
        else:
            return render_template('deleteitem.html',
                                   session=login_session,
                                   item=itemToDelete,
                                   category_name=category_name)
    else:
        return render_template('error.html')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
