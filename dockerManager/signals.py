# The world is a prison for the believer.
## https://www.youtube.com/watch?v=DWfNYztUM1U

from django.dispatch import Signal

## This event is fired before NitPanel core start installation of Docker
preDockerInstallation = Signal()

## This event is fired after NitPanel core finished intallation of Docker.
postDockerInstallation = Signal()
