# UdacityFSND_blog

This repository contains code for a blog site.  To run the code as setup you will need Python 2.7, Google AppEngine, and Gulp (along with NodeJS and npm).

Installation for Python can be found at [Python's site](https://www.python.org).

Google AppEngine can be downloaded from [Google](https://cloud.google.com/appengine/downloads).

To install NodeJS and NPM please refer to [NodeJS](https://nodejs.org/en/).

After installing npm, make sure to install Gulp globally on your machine.  Refer [here](https://github.com/gulpjs/gulp/blob/master/docs/getting-started.md) for instructions.

After these are installed you can clone this repository to your local machine.  From the main directory use the following commands:

`npm install` to get the Gulp packages utilized

then

`gulp` to run the default Gulp script that will process the Sass files to CSS and start the local dev server from Google AppEngine

If you will be editing the styling of the page using Sass the command `gulp style` can be used in a new terminal window to begin Sass's watch function to compile your css from Sass.

The blog will then be available at `localhost:8000`
