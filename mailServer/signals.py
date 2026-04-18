# The world is a prison for the believer.
## https://www.youtube.com/watch?v=DWfNYztUM1U

from django.dispatch import Signal

## This event is fired before NitPanel core start creation of an email account.
preSubmitEmailCreation = Signal()

## This event is fired after NitPanel core finished creation of an email account.
postSubmitEmailCreation = Signal()

## This event is fired before NitPanel core start deletion of an email account
preSubmitEmailDeletion = Signal()

## This event is fired after NitPanel core finished deletion of an email account
postSubmitEmailDeletion = Signal()

## This event is fired before NitPanel core start deletion of email forwarding.
preSubmitForwardDeletion = Signal()

## This event is fired after NitPanel core finished deletion of email forwarding.
postSubmitForwardDeletion = Signal()

## This event is fired before NitPanel core start creation of email forwarding.
preSubmitEmailForwardingCreation = Signal()

## This event is fired after NitPanel core finished creation of email forwarding.
postSubmitEmailForwardingCreation = Signal()

## This event is fired before NitPanel core start changing password for email account.
preSubmitPasswordChange = Signal()

## This event is fired after NitPanel core finished changing password for email account.
postSubmitPasswordChange = Signal()

## This event is fired before NitPanel core start generating dkim keys.
preGenerateDKIMKeys = Signal()

## This event is fired after NitPanel core finished generating dkim keys.
postGenerateDKIMKeys = Signal()