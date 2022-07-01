<template>
  <div class="page-header align-items-start min-vh-100 bg-veach-red">
    <span class="mask bg-gradient-dark opacity-7"></span>
    <div class="container my-auto">
      <div class="row">
        <div class="mx-auto w-50">
          <img
            src="@/assets/img/logos/veach-transperent.png"
            class="img-fluid"
            alt="VEACH"
          />
        </div>
      </div>
      <div class="row">
        <div class="col-lg-4 col-md-8 col-12 mx-auto">
          <div class="card z-index-0 fadeIn3 fadeInBottom">
            <div class="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
              <div class="bg-veach-bg shadow-dark border-radius-lg py-3 pe-1">
                <h4 class="text-veach-red font-weight-bolder text-center mt-2 mb-0">
                  Sign in
                </h4>
                <div class="row mt-3">
                  <div class="text-center ms-auto">
                      <a class="" href="https://jumpcloud.com/blog/how-to-create-a-new-sudo-user-manage-sudo-access-on-ubuntu-20-04">
                      <p class="text-veach-red text-lg">
                        Please sign in with a sudo user
                      </p>
                      </a>
                  </div>
                </div>
              </div>
            </div>
            <div class="card-body">
              <form role="form" class="text-start mt-3">
                <div class="mb-3">
                  <material-input id="email" type="email" label="Email" name="email" />
                </div>
                <div class="mb-3">
                  <material-input
                    id="password"
                    type="password"
                    label="Password"
                    name="password"
                  />
                </div>
                <material-switch id="rememberMe" name="rememberMe"
                  >Remember me</material-switch
                >
                <div class="text-center">
                  <material-button
                    class="my-4 mb-2"
                    variant="gradient"
                    color="dark"
                    fullWidth
                    >Sign in</material-button
                  >
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    <footer class="footer position-absolute bottom-2 py-2 w-100">
      <div class="container">
        <div class="row align-items-center justify-content-lg-between">
          <div class="col-12 col-md-6 my-auto">
            <div class="copyright text-center text-sm text-white text-lg-start">
              © {{ new Date().getFullYear() }}, made with
              <i class="fa fa-heart" aria-hidden="true"></i> by
              <a
                href="https://github.com/omeround3/veach"
                class="font-weight-bold text-white"
                target="_blank"
                >VEACH Team</a
              >
              for better security.
            </div>
          </div>
          <div class="col-12 col-md-6">
            <ul class="nav nav-footer justify-content-center justify-content-lg-end">
              <li class="nav-item">
                <a
                  href="https://github.com/omeround3/veach"
                  class="nav-link text-white"
                  target="_blank"
                  ><i class="fa fa-github"></i> GitHub</a
                >
              </li>
              <li class="nav-item">
                <a
                  href="https://github.com/omeround3/veach/blob/main/LICENSE"
                  class="nav-link pe-0 text-white"
                  target="_blank"
                  >License</a
                >
              </li>
            </ul>
          </div>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
import MaterialInput from "@/components/MaterialInput.vue";
import MaterialSwitch from "@/components/MaterialSwitch.vue";
import MaterialButton from "@/components/MaterialButton.vue";
import { mapMutations } from "vuex";

export default {
  name: "sign-in",
  components: {
    MaterialInput,
    MaterialSwitch,
    MaterialButton,
  },
  beforeMount() {
    this.toggleEveryDisplay();
    this.toggleHideConfig();
  },
  beforeUnmount() {
    this.toggleEveryDisplay();
    this.toggleHideConfig();
  },
  methods: {
    ...mapMutations(["toggleEveryDisplay", "toggleHideConfig"]),
  },
};
</script>
