# The world is a prison for the believer.

from django.dispatch import Signal

## This event is fired before NitPanel core load the create database template, this special event is used
## to create a beautiful names official plugin. Actual FTP account creation happens with event named preSubmitDBCreation and postSubmitDBCreation.
preCreateDatabase = Signal()

## See preCreateDatabase
postCreateDatabase = Signal()

## This event is fired before NitPanel core start creation of a database.
preSubmitDBCreation = Signal()

## This event is fired after NitPanel core finished creation of a database.
postSubmitDBCreation = Signal()

## This event is fired before NitPanel core start deletion of a database
preSubmitDatabaseDeletion = Signal()

## This event is fired after NitPanel core finished deletion of a database.
postSubmitDatabaseDeletion = Signal()

## This event is fired before NitPanel core start to change a database password.
preChangePassword = Signal()

## This event is fired after NitPanel core finished changing database password.
postChangePassword = Signal()