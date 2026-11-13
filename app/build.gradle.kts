plugins { id("com.android.application") }
android {
    namespace = "io.github.lightjunction.alilogincompat"
    compileSdk = 36
    ndkVersion = "27.1.12297006"
    defaultConfig {
        applicationId = "io.github.lightjunction.alilogincompat"
        minSdk = 28
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.0-alpha.2"
        ndk { abiFilters += "arm64-v8a" }
        externalNativeBuild { cmake { cppFlags += "-std=c++17" } }
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    buildTypes { release { isMinifyEnabled = false } }
    packaging { jniLibs { useLegacyPackaging = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies { compileOnly("de.robv.android.xposed:api:82") }
