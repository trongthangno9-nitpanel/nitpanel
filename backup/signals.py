# The world is a prison for the believer.

from django.dispatch import Signal

## This event is fired before NitPanel core load template for create backup page.
preBackupSite = Signal()

## This event is fired after NitPanel core load template for create backup page.
postBackupSite = Signal()

## This event is fired before NitPanel core load template for restore backup page.
preRestoreSite = Signal()

## This event is fired after NitPanel core load template for restore backup page.
postRestoreSite = Signal()

## This event is fired before NitPanel core start creating backup of a website
preSubmitBackupCreation = Signal()

## This event is fired before NitPanel core starts to load status of backup started earlier througb submitBackupCreation
preBackupStatus = Signal()

## This event is fired after NitPanel core has loaded backup status
postBackupStatus = Signal()

## This event is fired before NitPanel core start deletion of a backup
preDeleteBackup = Signal()

## This event is fired after NitPanel core finished the backup deletion
postDeleteBackup = Signal()

## This event is fired before NitPanel core start restoring a backup.
preSubmitRestore = Signal()

## This event is fired before NitPanel core starts to add a remote backup destination
preSubmitDestinationCreation = Signal()

## This event is fired after NitPanel core is finished adding remote backup destination
postSubmitDestinationCreation = Signal()

## This event is fired before NitPanel core starts to delete a backup destination
preDeleteDestination = Signal()

## This event is fired after NitPanel core finished deleting a backup destination
postDeleteDestination = Signal()

## This event is fired before NitPanel core start adding a backup schedule
preSubmitBackupSchedule = Signal()

## This event is fired after NitPanel core finished adding a backup schedule
postSubmitBackupSchedule = Signal()

## This event is fired before NitPanel core start the deletion of backup schedule
preScheduleDelete = Signal()

## This event is fired after NitPanel core finished the deletion of backup schedule
postScheduleDelete = Signal()

## This event is fired before NitPanel core star the remote backup process
preSubmitRemoteBackups = Signal()

## This event is fired after NitPanel core finished remote backup process
postSubmitRemoteBackups = Signal()

## This event is fired before NitPanel core star the remote backup process
preStarRemoteTransfer = Signal()

## This event is fired after NitPanel core finished remote backup process
postStarRemoteTransfer = Signal()

## This event is fired before NitPanel core start restore of remote backups
preRemoteBackupRestore = Signal()

## This event is fired after NitPanel core finished restoring remote backups in local server
postRemoteBackupRestore = Signal()
