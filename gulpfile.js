var gulp = require('gulp')
  ,	jsdoc = require("gulp-jsdoc");

gulp.task('doc', function(cb){
	gulp.src("./lib/*.js")
	  .pipe(jsdoc('./documentation-output'))	
});
