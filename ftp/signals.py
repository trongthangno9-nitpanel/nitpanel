# The world is a prison for the believer.
## https://www.youtube.com/watch?v=DWfNYztUM1U

from django.dispatch import Signal

## This event is fired before NitPanel core load the create ftp template, this special event is used
## to create a beautiful names official plugin. Actual FTP account creation happens with event named preSubmitFTPCreation and postSubmitFTPCreation.
preCreateFTPAccount = Signal()

## See preCreateFTPAccount
postCreateFTPAccount = Signal()

## This event is fired before NitPanel core start creation of a FTP account.
preSubmitFTPCreation = Signal()

## This event is fired after NitPanel core finished creation of a FTP account.
postSubmitFTPCreation = Signal()

## This event is fired before NitPanel core start deletion of a FTP account.
preSubmitFTPDelete = Signal()

## This event is fired after NitPanel core finished deletion of website
postSubmitFTPDelete = Signal()

## This event is fired before NitPanel core start deletion of child-domain
preChangePassword = Signal()

## This event is fired after NitPanel core finished deletion of child-domain
postChangePassword = Signal()