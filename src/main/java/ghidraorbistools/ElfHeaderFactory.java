package ghidraorbistools;

import java.lang.reflect.InvocationTargetException;

import generic.continues.GenericFactory;

public class ElfHeaderFactory<T> implements GenericFactory {

	@SuppressWarnings("unchecked")
	@Override
	public T create(Class<?> type, Object... args) {
		// TODO Auto-generated method stub
		T instance = null;
		try {
			instance = (T) type.getConstructor().newInstance();
		} catch (InstantiationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return instance;
	}
}
