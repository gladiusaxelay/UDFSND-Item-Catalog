# UDFSND-Item-Catalog

This project goal is to build a dynamic website with persistent data storage to create a web app that provides a general-purpose catalog service to its users.

This RESTful web application is built using the Python framework Flask along with implementing third-party OAuth authentication. The app keeps track of ownership of the categories/items to prevent users from changing entries that they don't own.

## Getting Started

1. Donwload and install [Vagrant](https://www.vagrantup.com/downloads.html), [VirtualBox](https://www.virtualbox.org/wiki/Downloads), [Python](https://www.python.org/downloads/).
2. Clone or download the following [repository](https://github.com/udacity/fullstack-nanodegree-vm).

### Prerequisites

* Unix style terminal
* Vagrant (VM configuration file available in the repository above)
* VirtualBox
* Python

### Installing

1. On the repository ```vagrant/``` sub-directory do ```vagrant up```. This will make Vagrant download and install the Linux image and dependencies. It may take a while.
2. After it finishes, run ```vagrant ssh``` to log in to this newly-installed VM.

## Running the code

* To run the catalog app do:

```
python database_setup.py
python app.py
```

* Open the browser and go to http://localhost:8080/categories

### JSON endpoints

API to return all items in the catalog:
```
/api/v1/catalog/JSON
```

API to return all categories in the catalog:
```
/api/v1/categories/JSON
```

API to return an item of the catalog:
```
/api/v1/categories/<int:category_id>/item/<int:category_item_id>/JSON
```

## Acknowledgments

* Vagrant VM configuration and DB provided by Udacity.
* Fromt-end done with [Materialize].(https://materializecss.com/)
* Catalog icon from [here](https://www.freeiconspng.com/img/7353).