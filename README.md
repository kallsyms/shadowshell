# ShadowShell


## Motive

Ever wanted to easily save the output of the last command you ran but forgot to redirect it,
run in `screen`/`tmux`, etc?


## Usage

* Run `shadowtermd.py` in the background (could be setup as an init service)
* Run `underscore.py` when you need to get the output of the last command in the current shell
    * Optional: `alias _='/path/to/underscore.py'` so you can easily do `_ > thing_i_wanted_to_log`
