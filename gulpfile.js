/*
  Gulp file that includes autmation for starting the local appengine
  devserver, uploading the project to Google's appengine for deployment,
  watching sass updates,
*/

var gulp = require('gulp');
var sass = require('gulp-sass');
var exec = require('child_process').exec;

// Sass compile task
gulp.task('styles', function() {
  gulp.src('css/**/*.scss')
      .pipe(sass().on('error', sass.logError))
      .pipe(gulp.dest('./css/'));
});

// Sass watch task
gulp.task('style', function() {
  gulp.watch('css/**/*.scss',['styles']);
});

// Devserver start task
gulp.task('devserver', function() {
  exec('python /opt/google_appengine/dev_appserver.py .',
    function(err, stdout, stderr) {
      console.log(stdout);
      console.log(stderr);
      cb(err);
  });
});

gulp.task('deploy', function() {
  exec('python /opt/google_appengine/appcfg.py -A blog-project-ac -V v1 update .',
    function(err, stdout, stderr) {
      console.log(stdout);
      console.log(stderr);
      cb(err);
    });
});

gulp.task('default', ['styles', 'devserver']);
