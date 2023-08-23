<script>
  export let items = [];
	export let selected;
</script>

<div class="bar noselect">
  {#each items as i}
    <div
        class="item"
        class:selected={selected === i}
        on:click={() => selected = i}
        on:keypress={() => selected = i}
    >
      {i}
    </div>
  {/each}
</div>

<style>
  .bar {
      margin: 5px 10px;
      display: flex;
      justify-content: space-evenly;
      align-items: center;
      border-bottom: 1px solid var(--col-inact);
      font-weight: bold;
  }

  .item {
      margin-bottom: -1px;
      padding: 0 5px;
      text-align: center;
      border-bottom: 1px solid var(--col-inact);
  }

  .item:hover {
      border-bottom: 1px solid var(--col-acnt);
      cursor: pointer;
  }

  .selected {
      border-bottom: 1px solid var(--col-ok);
  }
</style>
