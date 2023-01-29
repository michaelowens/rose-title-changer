// res.set_icon_with_id("file.ico", "your-icon-name-here");

use windres::Build;

fn main() {
    Build::new().compile("resources.rc").unwrap();
}
