<script>
	import IconMagnify from "../icons/IconMagnify.svelte";
	import { onMount } from "svelte";
	import Tooltip from "../Tooltip.svelte";

	export let items = [];
	export let resItems;
	export let options = [];

	let selected = '';
	let search = '';

	onMount(() => {
		if (options.length > 0) {
			selected = options[0].accessor;
		}
	});

	$: {
		if (!search) {
			resItems = items;
		} else {
			resItems = [...items.filter(i => {
				// This switch is a bit more annoying to maintain, but we can set a more strict CSP without `eval`
        if (options.length > 0) {
					switch (selected) {
            case 'email':
							return i.email.toLowerCase().includes(search) || i.email === search;
						case 'id':
							return i.id.toLowerCase().includes(search) || i.id === search;
						case 'name':
							return i.name.toLowerCase().includes(search) || i.name === search;
						case 'user_id':
							return i.user_id.toLowerCase().includes(search) || i.user_id === search;
          }
        } else {
	        return i.toLowerCase().includes(search) || i === search;
        }
			})];
		}
	}
</script>

<div class="container">
  {#if options.length > 1}
    <Tooltip text="Search by">
      <select class="opts" bind:value={selected}>
        {#each options as opt}
          <option value={opt.accessor}>{opt.label}</option>
        {/each}
      </select>
    </Tooltip>
  {/if}

  <div class="inputBar">
    <input
        class="input"
        type="text"
        name="search"
        bind:value={search}
        placeholder="Search"
    />
    <div class="magnify">
      <IconMagnify width={20}/>
    </div>
  </div>
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

    .input {
        margin: 0;
        width: 100%;
        padding-left: 25px;
    }

    .inputBar {
        position: relative;
    }

    .magnify {
        position: absolute;
        top: 2px;
        left: 2px;
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
