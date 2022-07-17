import { createStore } from "vuex";

export default createStore({
  state: {
    hideConfigButton: false,
    isPinned: true,
    showConfig: false,
    sidebarType: "bg-gradient-dark",
    isRTL: false,
    color: "danger",
    isNavFixed: false,
    isAbsolute: false,
    showNavs: true,
    showSidenav: true,
    showNavbar: true,
    showFooter: true,
    showMain: true,
    isDarkMode: false,
    navbarFixed:
      "position-sticky blur shadow-blur left-auto top-1 z-index-sticky px-0 mx-4",
    absolute: "position-absolute px-4 mx-0 w-100 z-index-2",
    username: null,
    password: null,
    token: window.localStorage.getItem("token"),
    scanStatus: null,
  },
  mutations: {
    toggleConfigurator(state) {
      state.showConfig = !state.showConfig;
    },
    navbarMinimize(state) {
      const sidenav_show = document.querySelector(".g-sidenav-show");

      if (sidenav_show.classList.contains("g-sidenav-pinned")) {
        sidenav_show.classList.remove("g-sidenav-pinned");
        state.isPinned = true;
      } else {
        sidenav_show.classList.add("g-sidenav-pinned");
        state.isPinned = false;
      }
    },
    navbarFixed(state) {
      if (state.isNavFixed === false) {
        state.isNavFixed = true;
      } else {
        state.isNavFixed = false;
      }
    },
    toggleEveryDisplay(state) {
      state.showNavbar = !state.showNavbar;
      state.showSidenav = !state.showSidenav;
      state.showFooter = !state.showFooter;
    },
    toggleHideConfig(state) {
      state.hideConfigButton = !state.hideConfigButton;
    },
    color(state, payload) {
      state.color = payload;
    },
    setUser(state, value) {
      state.username = value == null ? null : value;
    },
    setPassword(state, value) {
      state.password = value == null ? null : value;
    },
    setToken(state, value) {
      state.token = value == null ? null : value;
    },
    setScanStatus(state, value) {
      state.scanStatus = value == null ? null : value;
    },
  },
  actions: {
    setColor({ commit }, payload) {
      commit("color", payload);
    },
    setScanStatus({ commit }, status) {
      commit("setScanStatus", status);
      window.localStorage.setItem("scanStatus", status);
    },
    logout: ({ commit }) => {
      commit("setToken", null);
      window.localStorage.removeItem("username")
      window.localStorage.removeItem("password")
      window.localStorage.removeItem("token")
      window.localStorage.removeItem("scanStatus")
      // setTimeout(() => router.push("/sign-in"), 500);
    },
    login({ commit }, { username, password, token }) {
      if (token != "null") {
        commit("setUser", username);
        commit("setPassword", password);
        commit("setToken", token);
        window.localStorage.setItem("username", username);
        window.localStorage.setItem("password", password);
        window.localStorage.setItem("token", token);
        // setting timeout for the store to be completed 500 milliseconds in order for user details to load before redirecting to main dashboard
        // setTimeout(() => router.push("/"), 500);
      }
    },
  },
  getters: {
    getUsername: (state) => state.username,
    getPassword: (state) => state.password,
    getToken: (state) => state.token,
    getScanStatus: (state) => state.token,
    isLoggedIn: (state) => !!state.token,
  },
});
