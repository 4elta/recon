# Translations


## How to add a translation for an analyzer
For the automatic processing of strings you first need to mark them, that they need to be translated.
Therefore place a `_()` around the strings you want to translate. At the time of writing the string could be no f-string. Therefore you might need to split f-strings up. please use `message = <your text here>` as variable name if you want to add to an f-string. An examlpe can be seen below.

```sh 
print(_("Example string which will be translated"))
```
Do this for every string you want to translate.

Next we use the `pygettext.py` tool to extract the marked strings into a `.pot` file. You might have to find the `pygettext.py executable first. At time of writing mine was located in `/usr/lib/python3.11/Tools/i18n/`.
Below is an example for rdp.

```sh
/usr/lib/python3.11/Tools/i18n/pygettext.py -d rdp -o locales/rdp.pot analyzers/rdp/nmap.py
```

- `-d` is the domain for your translation and should be the same name as the analyzer you want to translate
- `-o` is the ouput file which should be also named like your analyzer
- the last argument 



Now you have to create the neccessary directories

```sh
# in the recon root
mkdir -p locales/<language short code>/LC_MESSAGES
```
afterwards copy the corresponding domain file of the analyzer located in `locales`. E.g. for rdp

```sh
cp locales/rdp.pot locales/<language short code>/LC_MESSAGES/rdp.po
```

Now you can add your translation. The `msgid` field contains the english string that will be matched. You can add your translation in the `msgstr` field. Save the file and run `msgfmt.py`.

For the example we will stick with rdp, but you have to replace rdp with the domain you are using

```sh
cd locales/<language short code>/LC_MESSAGES/
msgfmt.py -o rdp.mo rdp
```

you might have to look up where the `msgfmt` tool is located. At the time of writing it was placed in
`/usr/lib/python3.11/Tools/i18n/`

This will create an `rdp.mo` file in the current directory. Now it's time to test your translation. If everything works as you expect it, stage the \*.mo, \*.pot and \*.po file, commit it and open a pull request


## How to update an existing translation

First you have to mark strings for translation using the `\_()` function. Wrap the elements you want to translate in it.

Now create a new pot file which contains the old and new strings.

```sh
/usr/lib/python3.11/Tools/i18n/pygettext.py -d rdp -o locales/rdp.pot analyzers/rdp/nmap.py
```

now you can add the new `msgid`s to the existing \*.po files in all languages. 
Add your translation in the `msgstr` field and create the \*.mo file.

```sh
cd locales/<language short code>/LC_MESSAGES/
msgfmt.py -o rdp.mo rdp
```


## How to add a translation to an existing module

FIrst you have to create the neccessary directories

```sh
# in the recon root
mkdir -p locales/<language short code>/LC_MESSAGES
```
afterwards copy the corresponding domain file of the analyzer located in `locales`. E.g. for rdp

```sh
cp locales/rdp.pot locales/<language short code>/LC_MESSAGES/rdp.po
```

Now you can add your translation. The `msgid` field contains the english string that will be matched. You can add your translation in the `msgstr` field. Save the file and run `msgfmt.py`.

For the example we will stick with rdp, but you have to replace rdp with the domain you are using

```sh
cd locales/<language short code>/LC_MESSAGES/
msgfmt.py -o rdp.mo rdp
```

you might have to look up where the `msgfmt` tool is located. At the time of writing it was placed in
`/usr/lib/python3.11/Tools/i18n/`


This will create an `rdp.mo` file in the current directory. Now it's time to test your translation. If everything works as you expect it, stage the \*.mo file, commit it and open a pull request

 
