<template>
  <div class="container-fluid">
    <div class="page-header min-height-100 border-radius-xl mt-4">
      <span class="mask bg-gradient-danger opacity-6"></span>
    </div>
    <div class="card card-body mx-3 mx-md-4 mt-n6">
      <div class="row gx-4">
        <div class="col-auto">
          <div class="avatar avatar-xxl position-relative">
            <img src="@/assets/img/veach-transperent.png" alt="veach_image" class="shadow-sm w-100 border-radius-lg" />
          </div>
        </div>
        <div class="col-auto my-auto">
          <div class="h-100">
            <h5 class="mb-1">VEACH Settings</h5>
            <p class="mb-0 font-weight-normal text-sm">Customize your settings</p>
          </div>
        </div>
        <div class="mx-auto mt-3 col-lg-4 col-md-6 my-sm-auto ms-sm-auto me-sm-0">
          <div class="nav-wrapper position-relative end-0">
            <ul class="p-1 bg-transparent nav nav-pills nav-fill" role="tablist">
              <li class="nav-item">
                <a class="px-0 py-1 mb-0 nav-link active" data-bs-toggle="tab" href="javascript:;" role="tab"
                  aria-selected="true">
                  <svg class="text-dark" width="16px" height="16px" viewBox="0 0 40 40" version="1.1"
                    xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <title>settings</title>
                    <g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                      <g transform="translate(-2020.000000, -442.000000)" fill="#FFFFFF" fill-rule="nonzero">
                        <g transform="translate(1716.000000, 291.000000)">
                          <g transform="translate(304.000000, 151.000000)">
                            <polygon class="color-background" opacity="0.596981957"
                              points="18.0883333 15.7316667 11.1783333 8.82166667 13.3333333 6.66666667 6.66666667 0 0 6.66666667 6.66666667 13.3333333 8.82166667 11.1783333 15.315 17.6716667" />
                            <path class="color-background"
                              d="M31.5666667,23.2333333 C31.0516667,23.2933333 30.53,23.3333333 30,23.3333333 C29.4916667,23.3333333 28.9866667,23.3033333 28.48,23.245 L22.4116667,30.7433333 L29.9416667,38.2733333 C32.2433333,40.575 35.9733333,40.575 38.275,38.2733333 L38.275,38.2733333 C40.5766667,35.9716667 40.5766667,32.2416667 38.275,29.94 L31.5666667,23.2333333 Z"
                              opacity="0.596981957" />
                            <path class="color-background"
                              d="M33.785,11.285 L28.715,6.215 L34.0616667,0.868333333 C32.82,0.315 31.4483333,0 30,0 C24.4766667,0 20,4.47666667 20,10 C20,10.99 20.1483333,11.9433333 20.4166667,12.8466667 L2.435,27.3966667 C0.95,28.7083333 0.0633333333,30.595 0.00333333333,32.5733333 C-0.0583333333,34.5533333 0.71,36.4916667 2.11,37.89 C3.47,39.2516667 5.27833333,40 7.20166667,40 C9.26666667,40 11.2366667,39.1133333 12.6033333,37.565 L27.1533333,19.5833333 C28.0566667,19.8516667 29.01,20 30,20 C35.5233333,20 40,15.5233333 40,10 C40,8.55166667 39.685,7.18 39.1316667,5.93666667 L33.785,11.285 Z" />
                          </g>
                        </g>
                      </g>
                    </g>
                  </svg>
                  <span class="ms-1">Settings</span>
                </a>
              </li>
              <!-- <li class="nav-item">
                <a
                  class="px-0 py-1 mb-0 nav-link"
                  data-bs-toggle="tab"
                  href="javascript:;"
                  role="tab"
                  aria-selected="false"
                >
                  <svg
                    class="text-dark"
                    width="16px"
                    height="16px"
                    viewBox="0 0 40 44"
                    version="1.1"
                    xmlns="http://www.w3.org/2000/svg"
                    xmlns:xlink="http://www.w3.org/1999/xlink"
                  >
                    <title>document</title>
                    <g
                      stroke="none"
                      stroke-width="1"
                      fill="none"
                      fill-rule="evenodd"
                    >
                      <g
                        transform="translate(-1870.000000, -591.000000)"
                        fill="#FFFFFF"
                        fill-rule="nonzero"
                      >
                        <g transform="translate(1716.000000, 291.000000)">
                          <g transform="translate(154.000000, 300.000000)">
                            <path
                              class="color-background"
                              d="M40,40 L36.3636364,40 L36.3636364,3.63636364 L5.45454545,3.63636364 L5.45454545,0 L38.1818182,0 C39.1854545,0 40,0.814545455 40,1.81818182 L40,40 Z"
                              opacity="0.603585379"
                            />
                            <path
                              class="color-background"
                              d="M30.9090909,7.27272727 L1.81818182,7.27272727 C0.814545455,7.27272727 0,8.08727273 0,9.09090909 L0,41.8181818 C0,42.8218182 0.814545455,43.6363636 1.81818182,43.6363636 L30.9090909,43.6363636 C31.9127273,43.6363636 32.7272727,42.8218182 32.7272727,41.8181818 L32.7272727,9.09090909 C32.7272727,8.08727273 31.9127273,7.27272727 30.9090909,7.27272727 Z M18.1818182,34.5454545 L7.27272727,34.5454545 L7.27272727,30.9090909 L18.1818182,30.9090909 L18.1818182,34.5454545 Z M25.4545455,27.2727273 L7.27272727,27.2727273 L7.27272727,23.6363636 L25.4545455,23.6363636 L25.4545455,27.2727273 Z M25.4545455,20 L7.27272727,20 L7.27272727,16.3636364 L25.4545455,16.3636364 L25.4545455,20 Z"
                            />
                          </g>
                        </g>
                      </g>
                    </g>
                  </svg>
                  <span class="ms-1">Messages</span>
                </a>
              </li> -->
              <!-- <li class="nav-item">
                <a
                  class="px-0 py-1 mb-0 nav-link"
                  data-bs-toggle="tab"
                  href="javascript:;"
                  role="tab"
                  aria-selected="false"
                >
                  <svg
                    class="text-dark"
                    width="16px"
                    height="16px"
                    viewBox="0 0 40 40"
                    version="1.1"
                    xmlns="http://www.w3.org/2000/svg"
                    xmlns:xlink="http://www.w3.org/1999/xlink"
                  >
                    <title>settings</title>
                    <g
                      stroke="none"
                      stroke-width="1"
                      fill="none"
                      fill-rule="evenodd"
                    >
                      <g
                        transform="translate(-2020.000000, -442.000000)"
                        fill="#FFFFFF"
                        fill-rule="nonzero"
                      >
                        <g transform="translate(1716.000000, 291.000000)">
                          <g transform="translate(304.000000, 151.000000)">
                            <polygon
                              class="color-background"
                              opacity="0.596981957"
                              points="18.0883333 15.7316667 11.1783333 8.82166667 13.3333333 6.66666667 6.66666667 0 0 6.66666667 6.66666667 13.3333333 8.82166667 11.1783333 15.315 17.6716667"
                            />
                            <path
                              class="color-background"
                              d="M31.5666667,23.2333333 C31.0516667,23.2933333 30.53,23.3333333 30,23.3333333 C29.4916667,23.3333333 28.9866667,23.3033333 28.48,23.245 L22.4116667,30.7433333 L29.9416667,38.2733333 C32.2433333,40.575 35.9733333,40.575 38.275,38.2733333 L38.275,38.2733333 C40.5766667,35.9716667 40.5766667,32.2416667 38.275,29.94 L31.5666667,23.2333333 Z"
                              opacity="0.596981957"
                            />
                            <path
                              class="color-background"
                              d="M33.785,11.285 L28.715,6.215 L34.0616667,0.868333333 C32.82,0.315 31.4483333,0 30,0 C24.4766667,0 20,4.47666667 20,10 C20,10.99 20.1483333,11.9433333 20.4166667,12.8466667 L2.435,27.3966667 C0.95,28.7083333 0.0633333333,30.595 0.00333333333,32.5733333 C-0.0583333333,34.5533333 0.71,36.4916667 2.11,37.89 C3.47,39.2516667 5.27833333,40 7.20166667,40 C9.26666667,40 11.2366667,39.1133333 12.6033333,37.565 L27.1533333,19.5833333 C28.0566667,19.8516667 29.01,20 30,20 C35.5233333,20 40,15.5233333 40,10 C40,8.55166667 39.685,7.18 39.1316667,5.93666667 L33.785,11.285 Z"
                            />
                          </g>
                        </g>
                      </g>
                    </g>
                  </svg>
                  <span class="ms-1">Settings</span>
                </a>
              </li> -->
            </ul>
          </div>
        </div>
      </div>
      <div v-if="scanStatus == 'scanning'" class="row text-center">
        <h6 class="mb-0 text-danger">You Can't Change Settings While There Is A Scan In Progress</h6>
      </div>
      <div v-else class="row">
        <div class="mt-3 row">
          <div class="col-12 col-md-6 col-xl-6 position-relative">
            <div class="card card-plain h-100">
              <div class="p-3 pb-0 card-header">
                <h6 class="mb-0">Platform Settings</h6>
              </div>
              <div class="p-3 card-body">
                <h6 class="text-xs text-uppercase text-body font-weight-bolder">
                  SCAN SETTINGS
                </h6>
                <ul class="list-group">
                  <li class="px-0 border-0 list-group-item">
                    <material-switch id="flexSwitchCheckDefault1" class="ps-0 ms-0" name="flexSwitchCheckDefault1"
                      label-class="mb-0 text-body text-truncate w-80" :checked="isScanSoftware"
                      @click="setScanSettings('software')">Scan Software</material-switch>
                  </li>

                  <li class="px-0 border-0 list-group-item">
                    <material-switch id="flexSwitchCheckDefault2" class="ps-0 ms-0" name="flexSwitchCheckDefault2"
                      label-class="mb-0 text-body text-truncate w-80" :checked="isScanHardware"
                      @click="setScanSettings('hardware')">Scan Hardware</material-switch>
                  </li>
                </ul>
                <!-- <h6 class="mt-4 text-xs text-uppercase text-body font-weight-bolder">
                  Application
                </h6>
                <ul class="list-group">
                  <li class="px-0 border-0 list-group-item">
                    <material-badge variant="gradient" color="danger">
                      Remote Database Status
                    </material-badge>
                  </li>
                  <li class="px-0 border-0 list-group-item">
                    <material-badge variant="gradient" color="success">
                      Local Database Status
                    </material-badge>
                  </li>
                </ul> -->
                <h6 class="mt-7 text-xs text-uppercase text-body font-weight-bolder">
                  IMPACT INTERESTS
                </h6>
                <ul class="list-group">
                  <li class="px-0 border-0 list-group-item">
                    <div class="d-flex">
                      <span class="px-2">Attack Vector: </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_vector'].includes('NETWORK'), 'btn-veach-red': !rulesData['attack_vector'].includes('NETWORK') }"
                          style="font-size: 10px" @click="setRulesSettings('attack_vector', 'NETWORK')">
                          Network
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_vector'].includes('LOCAL'), 'btn-veach-red': !rulesData['attack_vector'].includes('LOCAL') }"
                          style="font-size: 10px" @click="setRulesSettings('attack_vector', 'LOCAL')">
                          Local
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_vector'].includes('PHYSICAL'), 'btn-veach-red': !rulesData['attack_vector'].includes('PHYSICAL') }"
                          style="font-size: 10px" @click="setRulesSettings('attack_vector', 'PHYSICAL')">
                          Physical
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_vector'].includes('ADJACENT_NETWORK'), 'btn-veach-red': !rulesData['attack_vector'].includes('ADJACENT_NETWORK') }"
                          style="font-size: 10px" @click="setRulesSettings('attack_vector', 'ADJACENT_NETWORK')">
                          Adjacent
                        </button>
                      </span>
                    </div>
                  </li>
                  <li class="px-0 border-0 list-group-item">
                    <div class="d-flex">
                      <span class="px-2">Attack Complexity: </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_complexity'] == 'LOW', 'btn-veach-red': rulesData['attack_complexity'] != 'LOW' }"
                          style="font-size: 10px" @click="setRulesSettings('attack_complexity', 'LOW')">
                          Low
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['attack_complexity'] == 'HIGH', 'btn-veach-red': rulesData['attack_complexity'] != 'HIGH' }"
                          style="font-size: 10px" @click="setRulesSettings('attack_complexity', 'HIGH')">
                          High
                        </button>
                      </span>
                    </div>
                  </li>
                  <li class="px-0 border-0 list-group-item">
                    <div class="d-flex">
                      <span class="px-2">Confidentiality Impact: </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['confidentiality_impact'] == 'NONE', 'btn-veach-red': rulesData['confidentiality_impact'] != 'NONE' }"
                          style="font-size: 10px" @click="setRulesSettings('confidentiality_impact', 'NONE')">
                          None
                        </button>
                      </span> <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['confidentiality_impact'] == 'LOW', 'btn-veach-red': rulesData['confidentiality_impact'] != 'LOW' }"
                          style="font-size: 10px" @click="setRulesSettings('confidentiality_impact', 'LOW')">
                          Low
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['confidentiality_impact'] == 'HIGH', 'btn-veach-red': rulesData['confidentiality_impact'] != 'HIGH' }"
                          style="font-size: 10px" @click="setRulesSettings('confidentiality_impact', 'HIGH')">
                          High
                        </button>
                      </span>
                    </div>
                  </li>
                  <li class="px-0 border-0 list-group-item">
                    <div class="d-flex">
                      <span class="px-2">Integrity Impact: </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['integrity_impact'] == 'NONE', 'btn-veach-red': rulesData['integrity_impact'] != 'NONE' }"
                          style="font-size: 10px" @click="setRulesSettings('integrity_impact', 'NONE')">
                          None
                        </button>
                      </span> <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['integrity_impact'] == 'LOW', 'btn-veach-red': rulesData['integrity_impact'] != 'LOW' }"
                          style="font-size: 10px" @click="setRulesSettings('integrity_impact', 'LOW')">
                          Low
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['integrity_impact'] == 'HIGH', 'btn-veach-red': rulesData['integrity_impact'] != 'HIGH' }"
                          style="font-size: 10px" @click="setRulesSettings('integrity_impact', 'HIGH')">
                          High
                        </button>
                      </span>
                    </div>
                  </li>
                  <li class="px-0 border-0 list-group-item">
                    <div class="d-flex">
                      <span class="px-2">Availability Impact: </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['availability_impact'] == 'NONE', 'btn-veach-red': rulesData['availability_impact'] != 'NONE' }"
                          style="font-size: 10px" @click="setRulesSettings('availability_impact', 'NONE')">
                          None
                        </button>
                      </span> <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['availability_impact'] == 'LOW', 'btn-veach-red': rulesData['availability_impact'] != 'LOW' }"
                          style="font-size: 10px" @click="setRulesSettings('availability_impact', 'LOW')">
                          Low
                        </button>
                      </span>
                      <span class="px-1">
                        <button type="button" class="btn"
                          :class="{ 'btn-veach-red-selected': rulesData['availability_impact'] == 'HIGH', 'btn-veach-red': rulesData['availability_impact'] != 'HIGH' }"
                          style="font-size: 10px" @click="setRulesSettings('availability_impact', 'HIGH')">
                          High
                        </button>
                      </span>
                    </div>
                  </li>
                </ul>
              </div>
            </div>
            <hr class="vertical dark" />
          </div>
          <div class="col-12 col-md-6 col-xl-4 mt-md-0 mt-4 position-relative">
            <profile-info-card title="System Information" description="System information goes here" :info="{
              cpu: 'Intel i5',
              ram: '4GB',
              storage: '200GB',
              linuxDist: 'bionic',
            }" :social="[
  {
    link: 'https://www.facebook.com/CreativeTim/',
    icon: 'fa-facebook',
  },
  {
    link: 'https://twitter.com/creativetim',
    icon: 'fa-twitter',
  },
  {
    link: 'https://www.instagram.com/creativetimofficial/',
    icon: 'fa-instagram',
  },
]" :action="{
  route: 'javascript:;',
  tooltip: 'System Information',
}" />
            <hr class="vertical dark" />
          </div>
          <div class="mt-4 col-12 col-xl-4 mt-xl-0">
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import ProfileInfoCard from "./components/ProfileInfoCard.vue";
import MaterialSwitch from "@/components/MaterialSwitch.vue";
import sophie from "@/assets/img/kal-visuals-square.jpg";
import marie from "@/assets/img/marie.jpg";
import ivana from "@/assets/img/ivana-square.jpg";
import peterson from "@/assets/img/team-4.jpg";
import nick from "@/assets/img/team-3.jpg";
import img1 from "@/assets/img/home-decor-1.jpg";
import img2 from "@/assets/img/home-decor-2.jpg";
import img3 from "@/assets/img/home-decor-3.jpg";
import team1 from "@/assets/img/team-1.jpg";
import team2 from "@/assets/img/team-2.jpg";
import team3 from "@/assets/img/team-3.jpg";
import team4 from "@/assets/img/team-4.jpg";

// import MaterialBadge from "@/components/MaterialBadge.vue";
import setNavPills from "@/assets/js/nav-pills.js";
import setTooltip from "@/assets/js/tooltip.js";
import api from "@/api/veach-api";

export default {
  name: "profile-overview",
  data() {
    return {
      rulesData: {
        attack_vector: [],
        attack_complexity: null,
        confidentiality_impact: null,
        integrity_impact: null,
        availability_impact: null
      },
      showMenu: false,
      sophie,
      marie,
      ivana,
      peterson,
      nick,
      img1,
      team1,
      team2,
      team3,
      team4,
      img2,
      img3,
      isScanHardware: false,
      isScanSoftware: false,
      scanStatus: "scanning",
      config: {
        headers: {
          'Accept': "application/json",
          'Authorization': `Token ${window.localStorage.getItem("token")}`,
        },
      },
    };
  },
  components: {
    ProfileInfoCard,
    // MaterialBadge,
    // DefaultProjectCard,
    MaterialSwitch,
    // MaterialAvatar,
  },
  created() {
    this.getScanStatus()
    this.getScanSettings()
    this.getRulesSettings()
  },
  mounted() {
    this.$store.state.isAbsolute = true;
    setNavPills();
    setTooltip();
    this.timer = setInterval(() => {
      this.getScanStatus()
    }, 2000);
  },
  beforeUnmount() {
    this.$store.state.isAbsolute = false;
    clearInterval(this.timer);
  },
  methods: {
    async getScanStatus() {
      var element = this;
      const res = await api.fetchScanStatus(this.config)
      if (res) {
        element.scanStatus = res.data["status"];
      }
    },
    getScanSettings() {
      api.fetchScanSettings(this.config)
        .then((res) => {
          this.isScanHardware = res.is_scan_hardware == "True" ? true : false;
          this.isScanSoftware = res.is_scan_software == "True" ? true : false;
        })
        .catch((error) => {
          console.error(error)
        });
    },
    setScanSettings(value) {
      if (value == "software") {
        this.isScanSoftware = !this.isScanSoftware
      }
      else if (value == "hardware") {
        this.isScanHardware = !this.isScanHardware
      }
      api.updateScanSettings(this.config, this.isScanSoftware, this.isScanHardware)
        .catch((error) => {
          console.error(error)
        });
    }, getRulesSettings() {
      api.fetchRulesSettings(this.config)
        .then((res) => {
          this.rulesData = res
        })
        .catch((error) => {
          console.error(error)
        });
    },
    setRulesSettings(rule, value) {
      if (rule === 'attack_vector') {
        if (this.rulesData[rule].includes(value)) {
          this.rulesData[rule].splice(this.rulesData[rule].indexOf(value), 1)
        }
        else {
          this.rulesData[rule].push(value)
        }
        api.updateRulesSettings(this.config, this.rulesData)
          .catch((error) => {
            console.error(error)
          });
      } else if (this.rulesData[rule] !== value) {
        this.rulesData[rule] = value
        api.updateRulesSettings(this.config, this.rulesData)
          .catch((error) => {
            console.error(error)
          });
      }
    }
  }
};
</script>
