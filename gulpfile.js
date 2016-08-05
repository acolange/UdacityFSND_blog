/*
  Gulp file that includes autmation for starting the local appengine
  devserver, uploading the project to Google's appengine for deployment,
  watching sass updates,
*/

var gulp = require('gulp');
var sass = require('gulp-sass');

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
