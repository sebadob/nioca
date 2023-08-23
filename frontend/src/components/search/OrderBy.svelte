<script>
	import { onMount } from "svelte";
	import IconBarsArrowDown from "../icons/IconBarsArrowDown.svelte";
	import IconBarsArrowUp from "../icons/IconBarsArrowUp.svelte";
    import Tooltip from "$lib/Tooltip.svelte";

	export let items = [];
	export let resItems;
	export let options = [];
	export let firstDirReverse = false;

	let selected = '';
	let direction = 1;

	onMount(() => {
		if (options.length > 0) {
			selected = options[0].accessor;
		}

		if (firstDirReverse) {
			switchDirection();
    }
	});

	$: if (items) {
		orderItems();
  }

	$: if (selected) {
		orderItems();
	}

	function orderItems() {
		let sorted = [...items];
		sorted.sort((a, b) => {
			// This switch is a bit more annoying to maintain, but we can set a more strict CSP without `eval`
			switch (selected) {
				case 'email':
					return a.email.localeCompare(b.email) * direction;
				case 'id':
					return a.id.localeCompare(b.id) * direction;
				case 'name':
					return a.name.localeCompare(b.name) * direction;
				case 'user_id':
					return a.user_id.localeCompare(b.user_id) * direction;
				case 'state':
					return a.state.localeCompare(b.state) * direction;
				case 'expires':
					return (new Date(a.exp) - new Date(b.exp)) * direction;
				case 'last_seen':
					return (new Date(a.last_seen) - new Date(b.last_seen)) * direction;
			}
		});
		resItems = [...sorted];
  }

	function switchDirection() {
		direction *= -1;
		orderItems();
  }
</script>

<div class="container">
  {#if options.length > 1}
    <Tooltip text="Order by">
      <select class="opts" bind:value={selected}>
        {#each options as opt}
          <option value={opt.accessor}>{opt.label}</option>
        {/each}
      </select>
    </Tooltip>
  {/if}

  {#if options.length > 0}
    <div class="icon" on:click={switchDirection} on:keypress={switchDirection}>
      {#if direction === 1}
        <IconBarsArrowUp />
      {:else}
        <IconBarsArrowDown />
      {/if}
    </div>
  {/if}
</div>

<style>
    .opts {
        margin-right: 15px;
    }

    .container {
        width: 100%;
        display: flex;
        align-items: center;
    }

    .icon {
        cursor: pointer;
    }

    select {
        padding: 2px;
        color: var(--col-text);
        background: white;
        font-size: 1.05em;
        border-radius: 3px;
        cursor: pointer;
        border: none;
        box-shadow: 3px 3px 3px var(--col-inact);
    }
</style>
