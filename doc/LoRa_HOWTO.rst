HOWTO use LoRa for querying data
================================


.. contents:: `Table of contents`
   :depth: 5




Introduction
++++++++++++

In this document, the use of LoRa's REST interface for reading and
writing data is described.

The examples are given with the ``curl`` terminal command but should
work equally well with a browser plugin capable of sending HTTP POST,
PUT and DELETE requests.

**Note:** As an example, the REST interface for Organisation is specified
here: http://beta.rammearkitektur.dk/index.php/LoRA_Organisationsservice

Please note that in comparison with this official implementation, our
system currently does not support the parameters ``-miljø`` and
``-version``.

As regards the parameter ``-miljø`` (which could be "-prod", "-test",
"-dev", etc.) we have been trying to convince the customer that we do
not recommend running test, development and production on the same
systems, so we would prefer not to support that parameter.

As regards the parameter ``-version``, we have deferred support for it
until we actually have more than one version of the protocol to support.

Acquire SAML token
++++++++++++++++++

A SAML STS token recognized by the system may be acquired by any means.
Please note that for login to proceed and the user's permissions to be
calculated correctly, the user must exist in the organisation, e.g. (as
in the case with referencedata.dk) by linking the IdP with an
Organisation service.

At present, however, a token is acquired by calling the function
`get-token` in the REST interface.

This can be done manually, through a browser, or through the command
line: ::

    curl https://moxdev.magenta-aps.dk/get-token -X POST -d "username=example&password=password"


This token will, in the current application, be valid for five minutes.
Different time spans or authentication schemes should be considered.


Reading data
++++++++++++

In order to search and read data from the REST interface, the HTTP GET
method is used.

It is only possible to search in a given class, i.e. in a definite point
in the hierarchy.

Read 
----


In order to *read* an object, you can access its URL with its UUID, e.g.
(and supposing we have stored the token as obtained above in the shell
variable AUTH_TOKEN): ::

    curl -k -sH "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -X GET https://moxdev.magenta-aps.dk/klassifikation/facet/81b362ee-8402-4371-873d-f8b4a749d241

The JSON representation of the desired object will be returned.

List
----

Apart from accessing a single object at its URL, you can also list
objects by specifying one or more UUIDs as parameters. E.g., to list two
objects of type OrganisationEnhed: ::

    curl -k -sH "Content-Type: application/json" -H "Authorization $AUTH_TOKEN" -X GET "https://moxdev.magenta-aps.dk/organisation/organisationenhed?uuid=7c6e38f8-e5b5-4b87-af52-9693e074f5ee&uuid=9765cdbf-9f42-4e9d-897b-909af549aba8"

The listed objects will be given in their JSON representation.

List operations may include the time parameters virkningFra and
virkningTil as well as registreringFra and registreringTil. In this
case, only the parts of the objects which fall within these restrictions
will be given.


Search
------


You can also *search* for an object by specifying values of attributes
or relations as search parameters. You can, e.g., find *all* objects of
class Klassifikation by searching for any value of "brugervendtnoegle": ::

    curl -k -sH "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -X GET https://organisation/organisation?brugervendtnoegle=%


Note that "%" has been used as wildcard. "bvn" can be used as shorthand
for "brugervendtnoegle", which is an attribute field that all objects
have, but apart from that, the attribute names should be spelled out.


It is possible to search for relations (links) as well by specifying
the value, which may be either an UUID or a URN. E.g., for finding all
instances of OrganisationFunktion which belongs to "Direktion": ::

    curl -k -sH "Content-Type: application/json" -H "Authorization $AUTH_TOKEN" -X GET https://moxdev.magenta-aps.dk/organisation/organisationfunktion?tilknyttedeenheder=urn:Direktion


Search parameters may be combined and may include the time restrictions
as for List, so it is possible to search for a value which must exist at
a given time or interval.

Note that while the result of a *list* or *read* operation is given as
the JSON representation of the object(s) returned, the result of a
*search* operation is always given as a list of UUIDs which may later be
retrieved with a list or read operation - e.g: ::

    agger@gefion:~/src/mox/interface_test$ curl -k -sH "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -X GET "https://moxdev.magenta-aps.dk/organisation/organisationenhed?brugervendtnoegle=Direktion&tilhoerer=urn:KL&enhedstype=urn:Direktion"
    {
    "results": [
        [
        "7c6e38f8-e5b5-4b87-af52-9693e074f5ee", 
        "9765cdbf-9f42-4e9d-897b-909af549aba8", 
        "3ca64809-acdb-443f-9316-aabb2ee6aff7", 
        "3eaa730c-7800-495a-9c6b-4688cdf7a61f", 
        "7d305acc-2a85-420b-9557-feead3dae339", 
        "1b1e2de1-6d95-4200-9b60-f85e70cc37cf", 
        "8680d348-688e-47f6-ad91-919ed75e4a5c", 
        "2fcf5fdf-fdfc-412a-b6ab-818cbdaecb5b", 
        "603e7977-65cb-47ca-ab82-c6308fd33d27", 
        "c1209882-a402-452b-8663-6c502f758b03", 
        "39a6ef88-ae26-4557-a48c-7d7c5662c609"
        ]
    ]
    }


Updating and creating data
++++++++++++++++++++++++++

To update existing and create new objects, the HTTP PUT and POST methods
are used, respectively. The data related to the object are supplied as
PUT or POST data as might e.g. be submitted from a form.

Examples of valid JSON data for creation, update and import can be found
in the directory `interface_test/test_data` in the source code.

Create 
------

To create a new object, POST the JSON representation of its attributes,
states and relations to the URL of the class - e.g., to create a new
Klasse. ::

    curl -k -H "Content-Type: application/json" -X POST -d "<JSON DATA>"-H "Authorization: $AUTH_TOKEN"  https://moxdev.magenta-aps.dk/klassifikation/klasse)


This will create a new Registrering of the object, valid from now to
infinity.


Update
------

To change an object, issue a PUT request containing the JSON
representation of the changes as they apply to the object's attributes,
states and relations.

The PUT request must be issued to the object's URL - i.e., including the
UUID.

An example: ::

    curl -k -sH "Content-Type: application/json" -X PUT -d "<JSON DATA>" -H "Authorization: $AUTH_TOKEN" https://moxdev.magenta-aps.dk/klassifikation/klasse/39a6ef88-ae26-4557-a48c-7d7c5662c609


Import
------

As in the case with update, an import is done with a PUT request. This
basically means that the distinction between an import and an update is
that in the case of an *import*, no object with the given UUID exists in
the system. One might say that an import is an update of an object which
does not (yet) exist in this system.

The data must contain a complete object in exactly the same format as
for the create operation, but must be PUT to the objects URL as given by
its UUID.

An example: ::

    curl -k -sH "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -X PUT -d "JSON DATA" /klassifikation/facet/1b1e2de1-6d95-4200-9b60-f85e70cc37cf


Passivating and deleting data
+++++++++++++++++++++++++++++

Passivate
---------

An object is passivated by sending a special update (PUT) request whose
JSON data only contains two fields, an optional note field and the life
cycle code "Passiv".

E.g., the JSON may look like this: ::

    {
        "Note": "Passivate this object!",
        "livscyklus": "Passiv"
    }


When an object is passive, it is no longer maintained and may not be
updated.


Delete
------

An object is deleted by sending a DELETE request. This might e.g. look
like this: ::

    curl -k -sH "Content-Type: application/json" -H "Authorization: $AUTH_TOKEN" -X DELETE -d "$(cat test_data/facet_slet.json)" https://moxdev.magenta-aps.dk/organisation/organisationenhed/7c6e38f8-e5b5-4b87-af52-9693e074f5ee

After an object is deleted, it may still be retrieved by a read or list
operation, but it will not appear in search results unless the
registreretTil and/or registreretFra indicate a period where it did
exist.

Appendix: Self-documentation
++++++++++++++++++++++++++++


* On a running LoRa system, it will always be possible to acquire, in
  JSON,  a sitemap of valid URLs on the ``/site-map/`` URL, e.g. located
  at https://moxdev.magenta-aps.dk/site-map.

* Similarly, for each service, a JSON representation of the
  hierarchy's classes and their fields may be found at the URL
  ``/<service>/classes/``, e.g. at
  https://moxdev.magenta-aps.dk/dokument/classes.



**TODO:** The JSON representing the classes should probably be
pretty-printed as is the case with the JSON for the sitemap. Also note
that the structure of each class is not completely analogous to the
structure of the input JSON as it uses the concept of "overrides". This
should also be fixed.


