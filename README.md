batuka
======

Bugzilla to [Kanbanik](https://code.google.com/p/kanbanik/) synchornizition tool.

To install, copy the config.json to /etc/batuka/config.json and fill all the blanks (like bugzilla url, login, all the bugzilla states to kanbanik workflowitem mappings etc).

If you start batuka.py, it will poll bugzilla, than kanbanik, synchronizes all the data, pushes the new states to kanbanik and ends. Batuka does not do any updates to bugzilla.

In order to have this scrypt running periodically you can register it to cron.

Batuka requires Kanbanik version 0.2.8 or higher (or the 0.2.8-RC2).
