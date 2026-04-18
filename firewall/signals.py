# The world is a prison for the believer.
## https://www.youtube.com/watch?v=DWfNYztUM1U

from django.dispatch import Signal

## This event is fired before NitPanel core load Firewall home template.
preFirewallHome = Signal()

## This event is fired after NitPanel core finished loading Firewall home template.
postFirewallHome = Signal()

## This event is fired before NitPanel core start adding a firewall rule.
preAddRule = Signal()

## This event is fired after NitPanel core finished adding a firewall rule.
postAddRule = Signal()

## This event is fired before NitPanel core start deleting a firewall rule.
preDeleteRule = Signal()

## This event is fired after NitPanel core finished deleting a firewall rule.
postDeleteRule = Signal()

## This event is fired before NitPanel core start to reload firewalld.
preReloadFirewall = Signal()

## This event is fired after NitPanel core finished reloading firewalld.
postReloadFirewall = Signal()

## This event is fired before NitPanel core start firewalld.
preStartFirewall = Signal()

## This event is fired after NitPanel core finished starting firewalld.
postStartFirewall = Signal()

## This event is fired before NitPanel core stop firewalld.
preStopFirewall = Signal()

## This event is fired after NitPanel core finished stopping firewalld.
postStopFirewall = Signal()

## This event is fired before NitPanel core start to fetch firewalld status.
preFirewallStatus = Signal()

## This event is fired after NitPanel core finished getting firewalld status.
postFirewallStatus = Signal()

## This event is fired before NitPanel core start loading template for securing ssh page.
preSecureSSH = Signal()

## This event is fired after NitPanel core finished oading template for securing ssh page.
postSecureSSH = Signal()

## This event is fired before NitPanel core start saving SSH configs.
preSaveSSHConfigs = Signal()

## This event is fired after NitPanel core finished saving saving SSH configs.
postSaveSSHConfigs = Signal()

## This event is fired before NitPanel core start deletion of an SSH key.
preDeleteSSHKey = Signal()

## This event is fired after NitPanel core finished deletion of an SSH key.
postDeleteSSHKey = Signal()

## This event is fired before NitPanel core start adding an ssh key.
preAddSSHKey = Signal()

## This event is fired after NitPanel core finished adding ssh key.
postAddSSHKey = Signal()

## This event is fired before NitPanel core load template for Mod Security Page.
preLoadModSecurityHome = Signal()

## This event is fired after NitPanel core is finished loading template for Mod Security Page.
postLoadModSecurityHome = Signal()

## This event is fired before NitPanel core start saving ModSecurity configurations.
preSaveModSecConfigurations = Signal()

## This event is fired after NitPanel core is saving ModSecurity configurations.
postSaveModSecConfigurations = Signal()

## This event is fired before NitPanel core start to load Mod Sec Rules Template Page.
preModSecRules = Signal()

## This event is fired after NitPanel core is finished loading Mod Sec Rules Template Page.
postModSecRules = Signal()

## This event is fired before NitPanel core start saving custom Mod Sec rules.
preSaveModSecRules = Signal()

## This event is fired after NitPanel core is finished saving custom Mod Sec rules.
postSaveModSecRules = Signal()


## This event is fired before NitPanel core start to load template for Mod Sec rules packs.
preModSecRulesPacks = Signal()

## This event is fired after NitPanel core is finished loading template for Mod Sec rules packs.
postModSecRulesPacks = Signal()

## This event is fired before NitPanel core fetch status of Comodo or OWASP rules.
preGetOWASPAndComodoStatus = Signal()

## This event is fired after NitPanel core is finished fetching status of Comodo or OWASP rules.
postGetOWASPAndComodoStatus = Signal()


## This event is fired before NitPanel core start installing Comodo or OWASP rules.
preInstallModSecRulesPack = Signal()

## This event is fired after NitPanel core is finished installing Comodo or OWASP rules.
postInstallModSecRulesPack = Signal()


## This event is fired before NitPanel core fetch available rules file for Comodo or OWASP.
preGetRulesFiles = Signal()

## This event is fired after NitPanel core is finished fetching available rules file for Comodo or OWASP.
postGetRulesFiles = Signal()

## This event is fired before NitPanel core start to enable or disable a rule file.
preEnableDisableRuleFile = Signal()

## This event is fired after NitPanel core is finished enabling or disabling a rule file.
postEnableDisableRuleFile = Signal()


## This event is fired before NitPanel core start to load template for CSF.
preCSF = Signal()

## This event is fired after NitPanel core is finished loading template for CSF.
postCSF = Signal()

## This event is fired before NitPanel core start to enable/disable CSF firewall.
preChangeStatus = Signal()

## This event is fired after NitPanel core is finished enabling/disabling CSF firewall.
postChangeStatus = Signal()

## This event is fired before NitPanel core start modifying CSF ports.
preModifyPorts = Signal()

## This event is fired after NitPanel core is finished modifying CSF ports.
postModifyPorts = Signal()

## This event is fired before NitPanel core start modifying IPs.
preModifyIPs = Signal()

## This event is fired after NitPanel core is finished modifying IPs.
postModifyIPs = Signal()