package dk.magenta.mox.agent;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by lars on 23-09-15.
 *
 * Map that holds multiple values for a given key
 */
public class ParameterMap<K,V> extends HashMap<K,ArrayList<V>> {

    public void add(K key, V value) {
        ArrayList<V> list = this.get(key);
        if (list == null) {
            list = new ArrayList<V>();
            this.put(key, list);
        }
        list.add(value);
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        for (K key : this.keySet()) {
            List<V> values = this.get(key);
            if (values != null) {
                JSONArray jsonArray = new JSONArray();
                for (V value : values) {
                    jsonArray.put((String) value);
                }
                jsonObject.put((String) key, jsonArray);
            }
        }
        return jsonObject;
    }

    public void populateFromJSON(JSONObject jsonObject) {
        for (String key : jsonObject.keySet()) {
            JSONArray values = jsonObject.optJSONArray(key);
            if (values != null) {
                for (int i=0; i<values.length(); i++) {
                    this.add((K) key, (V) values.get(i));
                }
            }
            String stringValue = jsonObject.optString(key);
            if (stringValue != null) {
                this.add((K) key, (V) stringValue);
            }
        }
    }

    public V getAtIndex(K key, int index) {
        if (this.containsKey(key)) {
            List<V> values = this.get(key);
            if (values.size() > index) {
                return values.get(index);
            }
        }
        return null;
    }

    public V getFirst(K key) {
        return this.getAtIndex(key, 0);
    }

    public Map<K,V> getFirstMap() {
        HashMap<K,V> map = new HashMap<>();
        for (K key : this.keySet()) {
            map.put(key, this.getFirst(key));
        }
        return map;
    }
}
