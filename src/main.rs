use nokhwa::{
    pixel_format::RgbAFormat,
    query,
    utils::{ApiBackend, RequestedFormat, RequestedFormatType},
    Camera,
};

fn main() {
    match query(ApiBackend::Auto) {
        Ok(cameras) => {
            for camera in &cameras {
                match Camera::new(
                    camera.index().clone(),
                    RequestedFormat::new::<RgbAFormat>(
                        RequestedFormatType::AbsoluteHighestResolution,
                    ),
                ) {
                    Ok(result) => {
                        println!("Camera: {:?}, name: {}", camera, camera.human_name());
                        println!("Resolution: {:?}", result.resolution());
                    }
                    Err(e) => {
                        println!("Failed to create camera: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Failed to query: {:?}", e);
        }
    }
}
