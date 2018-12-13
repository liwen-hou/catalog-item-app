## Catalog Item Application

This application allows users to browse items in different categories from the database and manage categories and items in each of the categories.

This documentation lists the requirements for running the application, and how to navigate within the application for different purposes.

### Requirements

The codes for the application is written in **python version 2.7**. The following modules need to be installed and imported for the application to run properly:

sqlalchemy - for handling Object Relationship Mapping between database and python
flask - the framework for web server development
oauth2client - for authentication with third party

### Getting Started

You will need to run the following two codes with the commands `python database_setup.py` and `python lotsofitems.py` before you start running the main project code in **project.py**. This is assuming you have all the required python modules installed in the environment where you run the codes.

After the code is running, the server will be listening on localhost port 5000. You can open a browser and enter http://localhost:5000 to access the application.

### Browsing categories

Users of the application can browse all available categories at
http://localhost:5000 or http://localhost:5000/category.

On the page, users can see a list of categories as well as the 10 most recently added catalog items, with the categories they belong to indicated.

### Browsing items in a category

A full list of items in a category can be viewed by clicking on the category name that the user wants to view. This will direct the user to the page http://localhost:5000/catalog/<category_name>/items/, where the list of items is displayed side by side with the list of categories.

### Browsing details of a certain item

By clicking on the name of a catalog item, the user will be directed to an item detail page, where a detailed description for the item will be displayed alongside the item name. The page is at https://localhost:5000/catalog/<category_name>/<item_name>/.

### Making changes to the application

Users can add a new category, editing the existing categories and delete an existing one. Similarly, they can also add a new item to a category, edit an existing item and delete one. Authentication rules apply as described below.

All users who wish to make changes to the application are required to login with a google account. To add a new category, users can click the **Add Category** button below the category list. If the user has not signed in, the page will be redirected to the login page where the user click on the google login button and sign in with a google account. After that, the user can add a new category at http://localhost:5000/category/new/.

Similarly, the user can add a new item with the **Add item** button below the item list when browsing each individual category. If the user has not signed in, the page will be redirected to the login page to sign in before a new item can be added at http://localhost:5000//category/<category_name>/item/new/.

To either edit or delete a category or an item in a category, the application will check whether the user is the owner of the category or item, by checking if the user id of the current user is the same as the user_id of the category/item. If the user ids are not the same, the user will be prompted with the error page which says you do not have the right.

After the verification, the user can then make changes for the following items with the corresponding paths. To edit or delete a category, go to the category page and click the Edit/Delete button below the category name. To edit or delete an item, go to the item detail page and click the edit/delete button there:

Edit a category - http://localhost:5000/category/<category_name>/edit/
Delete a category - http://localhost:5000/category/<category_name>/delete/
Edit an item - http://localhost:5000/category/<category_name>/<item_name>/edit/
Delete an item - http://localhost:5000/category/<category_name>/<item_name>/delete/

### User Login/Logout

A login button can be found on all pages on the upper right corner. The user can login there with a google account so that changes can be made to the catalog application. After signing in, a welcome message with the username will be displayed, with the option for the user to log out as well.


### Making API Call

There are two API endpoint available for the user to query the list of all items with their descriptions.
Endpoint 1: http://localhost:5000/catalog/JSON/. It returns a list of all items in the catalog
Endpoint 2: http://localhost:5000/catalog/<category_name>/<item_name>/JSON. It returns the information of a particular item specified.
