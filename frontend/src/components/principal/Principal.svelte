<script>
  import CheckIcon from "$lib/CheckIcon.svelte";
	import IconLogout from "../icons/IconLogout.svelte";
  import Tooltip from "$lib/Tooltip.svelte";
	import { fetchLogout } from "../../utils/dataFetching.js";
	import { deleteXsrfToken } from "../../utils/helpers.js";

	export let principal;

	let color = 'var(--col-text)';

	function onHoverEnter() {
		color = 'var(--col-acnt)';
  }

	function onHoverLeave() {
		color = 'var(--col-text)';
	}

	async function logout() {
    await fetchLogout();
    deleteXsrfToken();
    window.location.reload();
  }

</script>

<div class="container">
  <div class="head">
    {principal.email || 'root'}
  </div>

  <div class="row">
    <div class="label">
      Admin
    </div>
    <div class="value">
      <CheckIcon check={principal.isAdmin}/>
    </div>
  </div>

  <div class="row">
    <div class="label">
      User
    </div>
    <div class="value">
      <CheckIcon check={principal.isUser}/>
    </div>
  </div>

  <div class="row">
    <div class="label">
      Federated
    </div>
    <div class="value">
      <CheckIcon check={!principal.local}/>
    </div>
  </div>

  <div class="row">
    <div class="value"></div>
    <Tooltip text="Logout" xOffset={-80}>
      <div
          class="logout"
          on:mouseenter={onHoverEnter}
          on:mouseleave={onHoverLeave}
          on:click={logout}
          on:keypress={logout}
      >
        <IconLogout color={color} />
      </div>
    </Tooltip>
  </div>

</div>

<style>
    .container {
        padding: 10px;
        border: 1px solid var(--col-acnt);
        box-shadow: 0 0 3px 3px rgba(128, 128, 128, .2);
        background: rgba(255, 255, 255, .8);
    }

    .head {
        margin-bottom: 10px;
        font-weight: bold;
    }

    .label {
        width: 80px;
    }

    .logout {
        cursor: pointer;
    }

    .row {
        display: flex;
        align-items: center;
    }

    .value {
        flex: 1;
        text-align: right;
    }
</style>
